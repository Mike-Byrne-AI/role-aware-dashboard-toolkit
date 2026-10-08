from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from collections.abc import Iterable
from uuid import uuid4

GOVERNANCE_SCHEMA_VERSION = 1
VALID_GOVERNANCE_STATES = (
    "admissible",
    "needs_review",
    "escalated",
    "blocked",
    "replay_only",
)
VALID_POLICY_CHECK_RESULTS = (
    "pass",
    "warn",
    "fail",
    "waived",
)
VALID_ESCALATION_LEVELS = (
    "none",
    "review",
    "approver",
    "admin",
    "emergency",
)
VALID_GOVERNANCE_EVENT_TYPES = (
    "governance_created",
    "policy_evaluated",
    "state_changed",
    "escalation_changed",
    "case_synced",
)


# Native incidents remain open until explicitly closed, including monitoring
# and mitigated records. Retain the existing host-supplied status vocabulary.
INCIDENT_STATUS_OPEN = {
    "open", "monitoring", "mitigated", "triaging", "investigating", "mitigating", "watch",
}
SIGNOFF_APPROVED = {"approved", "acknowledged"}
BLOCKING_DECISION_STATES = {"rejected", "frozen"}
REPLAY_ONLY_DECISION_STATES = {"replay_only"}


def coerce_governance_state(state: str) -> str:
    value = str(state or "needs_review").strip().lower() or "needs_review"
    if value not in VALID_GOVERNANCE_STATES:
        raise ValueError(f"Invalid governance state '{state}'. Must be one of {VALID_GOVERNANCE_STATES}")
    return value



def coerce_policy_check_result(result: str) -> str:
    value = str(result or "pass").strip().lower() or "pass"
    if value not in VALID_POLICY_CHECK_RESULTS:
        raise ValueError(f"Invalid policy check result '{result}'. Must be one of {VALID_POLICY_CHECK_RESULTS}")
    return value



def coerce_escalation_level(level: str) -> str:
    value = str(level or "none").strip().lower() or "none"
    if value not in VALID_ESCALATION_LEVELS:
        raise ValueError(f"Invalid escalation level '{level}'. Must be one of {VALID_ESCALATION_LEVELS}")
    return value



def build_policy_check(
    check_id: str,
    title: str,
    result: str,
    *,
    detail: str = "",
    blocker: bool = False,
    refs: dict[str, Any] | None = None,
    required_roles: Iterable[str] | None = None,
) -> dict[str, Any]:
    return {
        "check_id": str(check_id or "").strip(),
        "title": str(title or "").strip(),
        "result": coerce_policy_check_result(result),
        "detail": str(detail or ""),
        "blocker": bool(blocker),
        "required_roles": _normalize_roles(required_roles),
        "refs": dict(refs or {}),
    }



def build_governance_record(
    case: dict[str, Any],
    *,
    decisions: list[dict[str, Any]] | None = None,
    incidents: list[dict[str, Any]] | None = None,
    signoffs: list[dict[str, Any]] | None = None,
    governance_id: str = "",
    actor: str = "",
    role: str = "",
    source: str = "ui",
    existing: dict[str, Any] | None = None,
) -> dict[str, Any]:
    case_copy = dict(case or {})
    evaluation = evaluate_case_governance(
        case_copy,
        decisions=decisions,
        incidents=incidents,
        signoffs=signoffs,
    )
    now = _iso_now()
    if existing:
        record = dict(existing)
        previous_state = str(record.get("state") or "")
        previous_escalation = str(record.get("escalation_level") or "")
        previous_summary = str(record.get("summary_text") or "")
        history = list(record.get("history") or [])
    else:
        record = {
            "schema_version": GOVERNANCE_SCHEMA_VERSION,
            "governance_id": str(governance_id or f"gov_{uuid4().hex[:12]}"),
            "created_at": now,
            "history": [],
        }
        previous_state = ""
        previous_escalation = ""
        previous_summary = ""
        history = []
        history.append({
            "ts": now,
            "event_type": "governance_created",
            "actor": str(actor or ""),
            "role": str(role or ""),
            "source": str(source or "ui"),
            "detail": "Governance record created from case context.",
        })

    record.update(
        {
            "schema_version": GOVERNANCE_SCHEMA_VERSION,
            "governance_id": str(record.get("governance_id") or governance_id or f"gov_{uuid4().hex[:12]}"),
            "case_id": str(case_copy.get("case_id") or ""),
            "created_at": str(record.get("created_at") or now),
            "updated_at": now,
            "actor": str(actor or case_copy.get("actor") or ""),
            "role": str(role or case_copy.get("role") or ""),
            "source": str(source or "ui"),
            "state": evaluation["state"],
            "severity": evaluation["severity"],
            "priority": str(case_copy.get("priority") or "normal"),
            "escalation_level": evaluation["escalation_level"],
            "case_state": str(case_copy.get("state") or "open"),
            "linked_run_ids": _normalize_strings(case_copy.get("linked_run_ids") or []),
            "linked_decision_ids": _normalize_strings(case_copy.get("linked_decision_ids") or []),
            "linked_incident_ids": _normalize_strings(case_copy.get("linked_incident_ids") or []),
            "policy_checks": evaluation["policy_checks"],
            "approval_requirements": evaluation["approval_requirements"],
            "blocked_actions": evaluation["blocked_actions"],
            "allowed_next_actions": evaluation["allowed_next_actions"],
            "summary_text": evaluation["summary_text"],
            "blocker_count": evaluation["blocker_count"],
            "warning_count": evaluation["warning_count"],
            "refs": {
                "run_ids": _normalize_strings(case_copy.get("linked_run_ids") or []),
                "decision_ids": _normalize_strings(case_copy.get("linked_decision_ids") or []),
                "incident_ids": _normalize_strings(case_copy.get("linked_incident_ids") or []),
            },
        }
    )

    detail = evaluation["summary_text"]
    if previous_state != evaluation["state"]:
        history.append(
            {
                "ts": now,
                "event_type": "state_changed",
                "actor": str(actor or ""),
                "role": str(role or ""),
                "source": str(source or "ui"),
                "from_state": previous_state,
                "to_state": evaluation["state"],
                "detail": detail,
            }
        )
    if previous_escalation != evaluation["escalation_level"]:
        history.append(
            {
                "ts": now,
                "event_type": "escalation_changed",
                "actor": str(actor or ""),
                "role": str(role or ""),
                "source": str(source or "ui"),
                "from_level": previous_escalation,
                "to_level": evaluation["escalation_level"],
                "detail": detail,
            }
        )
    if previous_summary != detail or not history or history[-1].get("event_type") == "governance_created":
        history.append(
            {
                "ts": now,
                "event_type": "policy_evaluated",
                "actor": str(actor or ""),
                "role": str(role or ""),
                "source": str(source or "ui"),
                "detail": detail,
            }
        )
    record["history"] = history
    return record



def sync_governance_record(
    governance: dict[str, Any],
    *,
    case: dict[str, Any],
    decisions: list[dict[str, Any]] | None = None,
    incidents: list[dict[str, Any]] | None = None,
    signoffs: list[dict[str, Any]] | None = None,
    actor: str = "",
    role: str = "",
    source: str = "ui",
) -> dict[str, Any]:
    return build_governance_record(
        case,
        decisions=decisions,
        incidents=incidents,
        signoffs=signoffs,
        governance_id=str(governance.get("governance_id") or ""),
        actor=actor,
        role=role,
        source=source,
        existing=governance,
    )



def evaluate_case_governance(
    case: dict[str, Any],
    *,
    decisions: list[dict[str, Any]] | None = None,
    incidents: list[dict[str, Any]] | None = None,
    signoffs: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    decisions_list = [dict(item) for item in list(decisions or [])]
    incidents_list = [dict(item) for item in list(incidents or [])]
    signoffs_list = [dict(item) for item in list(signoffs or [])]
    severity = derive_case_severity(case, incidents=incidents_list)
    approval_requirements = derive_approval_requirements(severity, signoffs=signoffs_list)
    unresolved_incidents = _unresolved_incidents(incidents_list)
    policy_checks = [
        _build_evidence_linkage_check(case),
        _build_incident_severity_gate_check(unresolved_incidents),
        *_build_decision_gate_checks(decisions_list),
        _build_approval_coverage_check(severity, approval_requirements=approval_requirements),
        _build_closure_consistency_check(case, unresolved_incidents=unresolved_incidents),
    ]

    escalation_level = derive_escalation_level(severity, policy_checks=policy_checks, approval_requirements=approval_requirements)
    state = derive_governance_state(policy_checks=policy_checks, escalation_level=escalation_level)
    blocked_actions = blocked_actions_for_governance(state, approval_requirements=approval_requirements, unresolved_incidents=unresolved_incidents)
    allowed_next_actions = allowed_actions_for_governance(
        state,
        approval_requirements=approval_requirements,
        unresolved_incidents=unresolved_incidents,
        has_decisions=bool(decisions_list),
    )
    summary_text = _build_summary_text(
        state=state,
        severity=severity,
        escalation_level=escalation_level,
        approval_requirements=approval_requirements,
        unresolved_incidents=unresolved_incidents,
        policy_checks=policy_checks,
    )
    blocker_count, warning_count = _policy_result_counts(policy_checks)
    return {
        "severity": severity,
        "escalation_level": escalation_level,
        "state": state,
        "policy_checks": policy_checks,
        "approval_requirements": approval_requirements,
        "blocked_actions": blocked_actions,
        "allowed_next_actions": allowed_next_actions,
        "summary_text": summary_text,
        "blocker_count": blocker_count,
        "warning_count": warning_count,
    }


def _build_evidence_linkage_check(case: dict[str, Any]) -> dict[str, Any]:
    linked_refs = sum(
        len(list(case.get(field) or []))
        for field in ("linked_run_ids", "linked_decision_ids", "linked_incident_ids", "linked_narrative_ids", "linked_note_ids")
    )
    return build_policy_check(
        "evidence_linkage",
        "Linked evidence present",
        "pass" if linked_refs > 0 else "warn",
        detail="Case includes linked runs/incidents/decisions." if linked_refs > 0 else "Case has no linked evidence yet.",
    )


def _unresolved_incidents(incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [item for item in incidents if str(item.get("status") or "").strip().lower() in INCIDENT_STATUS_OPEN]


def _build_incident_severity_gate_check(unresolved_incidents: list[dict[str, Any]]) -> dict[str, Any]:
    highest_open_severity = _highest_incident_severity(unresolved_incidents)
    incident_ids = [str(item.get("incident_id") or "") for item in unresolved_incidents]
    if highest_open_severity == "critical":
        return build_policy_check(
            "incident_severity_gate",
            "Open incident severity gate",
            "fail",
            detail="Critical open incident requires emergency handling before live changes.",
            blocker=True,
            refs={"incident_ids": incident_ids},
        )
    if highest_open_severity == "high":
        return build_policy_check(
            "incident_severity_gate",
            "Open incident severity gate",
            "warn",
            detail="High severity open incident should be mitigated or approved before live changes.",
            required_roles=["Approver"],
            refs={"incident_ids": incident_ids},
        )
    return build_policy_check(
        "incident_severity_gate",
        "Open incident severity gate",
        "pass",
        detail="No high-severity open incidents detected.",
    )


def _build_decision_gate_checks(decisions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    decision_states = {
        str(item.get("state") or "").strip().lower()
        for item in decisions
        if str(item.get("state") or "").strip()
    }
    replay_only_decisions = sorted(decision_states.intersection(REPLAY_ONLY_DECISION_STATES))
    blocking_decisions = sorted(decision_states.intersection(BLOCKING_DECISION_STATES))
    checks: list[dict[str, Any]] = []
    if replay_only_decisions:
        checks.append(
            build_policy_check(
                "replay_gate",
                "Replay-only decision gate",
                "fail",
                detail="At least one linked decision is replay-only; live mutation is blocked.",
                blocker=True,
                refs={"decision_states": replay_only_decisions},
            )
        )
    else:
        checks.append(
            build_policy_check(
                "replay_gate",
                "Replay-only decision gate",
                "pass",
                detail="No replay-only linked decisions detected.",
            )
        )
    if blocking_decisions:
        checks.append(
            build_policy_check(
                "decision_health",
                "Blocking decision states",
                "fail",
                detail=f"Blocking linked decision state(s): {', '.join(blocking_decisions)}.",
                blocker=True,
                refs={"decision_states": blocking_decisions},
            )
        )
    else:
        checks.append(
            build_policy_check(
                "decision_health",
                "Blocking decision states",
                "pass",
                detail="No rejected/frozen linked decisions detected.",
            )
        )
    return checks


def _build_approval_coverage_check(severity: str, *, approval_requirements: dict[str, Any]) -> dict[str, Any]:
    missing_roles = list(approval_requirements.get("missing_roles") or [])
    required_roles = list(approval_requirements.get("required_roles") or [])
    if missing_roles:
        return build_policy_check(
            "approval_coverage",
            "Severity-based approval coverage",
            "fail" if severity == "critical" else "warn",
            detail=f"Missing required signoff role(s): {', '.join(missing_roles)}.",
            blocker=severity == "critical",
            required_roles=missing_roles,
            refs={"required_roles": required_roles},
        )
    return build_policy_check(
        "approval_coverage",
        "Severity-based approval coverage",
        "pass",
        detail="Required signoff roles are satisfied for current severity.",
        required_roles=required_roles,
    )


def _build_closure_consistency_check(
    case: dict[str, Any],
    *,
    unresolved_incidents: list[dict[str, Any]],
) -> dict[str, Any]:
    case_state = str(case.get("state") or "open").strip().lower() or "open"
    if case_state == "closed" and unresolved_incidents:
        return build_policy_check(
            "closure_consistency",
            "Closed case consistency",
            "warn",
            detail="Case is marked closed while linked incidents remain open.",
        )
    return build_policy_check(
        "closure_consistency",
        "Closed case consistency",
        "pass",
        detail="Case state is consistent with linked incident status.",
    )


def _policy_result_counts(policy_checks: list[dict[str, Any]]) -> tuple[int, int]:
    blocker_count = sum(1 for item in policy_checks if item["result"] == "fail" and item.get("blocker"))
    warning_count = sum(1 for item in policy_checks if item["result"] == "warn")
    return blocker_count, warning_count



def derive_case_severity(case: dict[str, Any], *, incidents: list[dict[str, Any]] | None = None) -> str:
    priority = _priority_to_severity(str(case.get("priority") or "normal"))
    incident_severity = _highest_incident_severity(list(incidents or []))
    return _max_severity(priority, incident_severity)



def derive_approval_requirements(severity: str, *, signoffs: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    required_roles = required_roles_for_severity(severity)
    satisfied_roles = sorted(
        {
            str(item.get("role") or "").strip()
            for item in list(signoffs or [])
            if str(item.get("decision") or "").strip().lower() in SIGNOFF_APPROVED and str(item.get("role") or "").strip()
        },
        key=lambda value: value.lower(),
    )
    missing_roles = [role for role in required_roles if role not in satisfied_roles]
    return {
        "required_roles": required_roles,
        "satisfied_roles": satisfied_roles,
        "missing_roles": missing_roles,
        "is_satisfied": not missing_roles,
        "minimum_signoff_count": len(required_roles),
    }



def required_roles_for_severity(severity: str) -> list[str]:
    normalized = str(severity or "medium").strip().lower() or "medium"
    if normalized == "critical":
        return ["Approver", "Admin"]
    if normalized == "high":
        return ["Approver"]
    return []



def derive_escalation_level(
    severity: str,
    *,
    policy_checks: list[dict[str, Any]] | None = None,
    approval_requirements: dict[str, Any] | None = None,
) -> str:
    checks = list(policy_checks or [])
    requirements = dict(approval_requirements or {})
    if any(item.get("check_id") == "incident_severity_gate" and item.get("result") == "fail" for item in checks):
        return "emergency"
    missing_roles = list(requirements.get("missing_roles") or [])
    if "Admin" in missing_roles or str(severity or "") == "critical":
        return "admin"
    if "Approver" in missing_roles or str(severity or "") == "high":
        return "approver"
    if any(item.get("result") == "warn" for item in checks):
        return "review"
    return "none"



def derive_governance_state(*, policy_checks: list[dict[str, Any]] | None = None, escalation_level: str = "none") -> str:
    checks = list(policy_checks or [])
    if any(item.get("check_id") == "replay_gate" and item.get("result") == "fail" for item in checks):
        return "replay_only"
    if any(item.get("result") == "fail" and item.get("blocker") for item in checks):
        return "blocked"
    if escalation_level in {"approver", "admin", "emergency"}:
        return "escalated"
    if escalation_level == "review" or any(item.get("result") == "warn" for item in checks):
        return "needs_review"
    return "admissible"



def blocked_actions_for_governance(
    state: str,
    *,
    approval_requirements: dict[str, Any] | None = None,
    unresolved_incidents: list[dict[str, Any]] | None = None,
) -> list[str]:
    blocked: list[str] = []
    missing_roles = list((approval_requirements or {}).get("missing_roles") or [])
    if state in {"needs_review", "escalated", "blocked", "replay_only"}:
        blocked.extend(["approve_release", "promote_changes"])
    if state in {"blocked", "replay_only"}:
        blocked.append("apply_live_changes")
    if missing_roles or unresolved_incidents:
        blocked.append("close_case")
    return sorted(set(blocked))



def allowed_actions_for_governance(
    state: str,
    *,
    approval_requirements: dict[str, Any] | None = None,
    unresolved_incidents: list[dict[str, Any]] | None = None,
    has_decisions: bool = False,
) -> list[str]:
    actions = ["add_evidence", "link_case_record"]
    missing_roles = list((approval_requirements or {}).get("missing_roles") or [])
    if missing_roles:
        actions.extend(["request_signoff", "escalate_case"])
    if unresolved_incidents:
        actions.append("mitigate_incident")
    if has_decisions:
        actions.append("review_decision")
    if state in {"blocked", "replay_only"}:
        actions.append("replay_checkpoint")
    if state == "admissible":
        actions.extend(["apply_live_changes", "close_case"])
    if state in {"needs_review", "escalated"}:
        actions.append("request_review")
    blocked = blocked_actions_for_governance(
        state, approval_requirements=approval_requirements,
        unresolved_incidents=unresolved_incidents,
    )
    return sorted(set(actions).difference(blocked))



def governance_summary(governance: dict[str, Any]) -> dict[str, Any]:
    record = dict(governance or {})
    requirements = dict(record.get("approval_requirements") or {})
    return {
        "governance_id": str(record.get("governance_id") or ""),
        "case_id": str(record.get("case_id") or ""),
        "state": str(record.get("state") or ""),
        "severity": str(record.get("severity") or ""),
        "priority": str(record.get("priority") or ""),
        "case_state": str(record.get("case_state") or ""),
        "escalation_level": str(record.get("escalation_level") or "none"),
        "required_roles": list(requirements.get("required_roles") or []),
        "missing_roles": list(requirements.get("missing_roles") or []),
        "satisfied_roles": list(requirements.get("satisfied_roles") or []),
        "blocked_action_count": len(list(record.get("blocked_actions") or [])),
        "allowed_next_actions": list(record.get("allowed_next_actions") or []),
        "blocker_count": int(record.get("blocker_count") or 0),
        "warning_count": int(record.get("warning_count") or 0),
        "summary_text": str(record.get("summary_text") or ""),
    }



def summarize_governance(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    rows = [dict(item) for item in list(records or [])]
    state_counts: dict[str, int] = {}
    escalation_counts: dict[str, int] = {}
    severity_counts: dict[str, int] = {}
    for item in rows:
        state = str(item.get("state") or "")
        escalation = str(item.get("escalation_level") or "none")
        severity = str(item.get("severity") or "")
        if state:
            state_counts[state] = state_counts.get(state, 0) + 1
        if escalation:
            escalation_counts[escalation] = escalation_counts.get(escalation, 0) + 1
        if severity:
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
    return {
        "governance_count": len(rows),
        "state_counts": state_counts,
        "escalation_counts": escalation_counts,
        "severity_counts": severity_counts,
        "blocked_count": sum(1 for item in rows if str(item.get("state") or "") in {"blocked", "replay_only"}),
    }



def _build_summary_text(
    *,
    state: str,
    severity: str,
    escalation_level: str,
    approval_requirements: dict[str, Any],
    unresolved_incidents: list[dict[str, Any]],
    policy_checks: list[dict[str, Any]],
) -> str:
    missing_roles = list(approval_requirements.get("missing_roles") or [])
    parts = [f"Governance state is {state} at {severity} severity"]
    if escalation_level != "none":
        parts.append(f"with {escalation_level} escalation")
    if missing_roles:
        parts.append(f"missing signoff roles: {', '.join(missing_roles)}")
    if unresolved_incidents:
        parts.append(f"open incidents: {len(unresolved_incidents)}")
    failed = [item.get("title", "policy check") for item in policy_checks if item.get("result") == "fail"]
    if failed:
        parts.append(f"failed checks: {', '.join(str(item) for item in failed)}")
    return "; ".join(parts) + "."



def _priority_to_severity(priority: str) -> str:
    value = str(priority or "normal").strip().lower() or "normal"
    if value == "critical":
        return "critical"
    if value == "high":
        return "high"
    if value == "low":
        return "low"
    return "medium"



def _highest_incident_severity(incidents: list[dict[str, Any]]) -> str:
    if not incidents:
        return "low"
    level = "low"
    for item in incidents:
        candidate = str(item.get("severity") or "low").strip().lower() or "low"
        level = _max_severity(level, candidate)
    return level



def _max_severity(left: str, right: str) -> str:
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    left_norm = str(left or "low").strip().lower() or "low"
    right_norm = str(right or "low").strip().lower() or "low"
    left_norm = "medium" if left_norm == "normal" else left_norm
    right_norm = "medium" if right_norm == "normal" else right_norm
    return left_norm if order.get(left_norm, 0) >= order.get(right_norm, 0) else right_norm



def _normalize_roles(values: Iterable[str] | None) -> list[str]:
    rows = [str(value).strip() for value in list(values or []) if str(value).strip()]
    rows = sorted(set(rows), key=lambda value: value.lower())
    return rows



def _normalize_strings(values: Iterable[Any]) -> list[str]:
    rows = [str(value).strip() for value in list(values or []) if str(value).strip()]
    return sorted(set(rows), key=lambda value: value.lower())



def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


__all__ = [
    "GOVERNANCE_SCHEMA_VERSION",
    "VALID_ESCALATION_LEVELS",
    "VALID_GOVERNANCE_EVENT_TYPES",
    "VALID_GOVERNANCE_STATES",
    "VALID_POLICY_CHECK_RESULTS",
    "allowed_actions_for_governance",
    "blocked_actions_for_governance",
    "build_governance_record",
    "build_policy_check",
    "coerce_escalation_level",
    "coerce_governance_state",
    "coerce_policy_check_result",
    "derive_approval_requirements",
    "derive_case_severity",
    "derive_escalation_level",
    "derive_governance_state",
    "evaluate_case_governance",
    "governance_summary",
    "required_roles_for_severity",
    "summarize_governance",
    "sync_governance_record",
]
