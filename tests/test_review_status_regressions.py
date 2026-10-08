"""Incident lifecycle and governance recommendations must agree across records."""

from copy import deepcopy

import pytest

from role_aware_dashboard_toolkit.caseboard import build_case_record
from role_aware_dashboard_toolkit.governance import (
    VALID_GOVERNANCE_STATES,
    allowed_actions_for_governance,
    blocked_actions_for_governance,
    evaluate_case_governance,
)
from role_aware_dashboard_toolkit.operator_memory import (
    VALID_INCIDENT_SEVERITIES,
    VALID_INCIDENT_STATUSES,
    build_incident_record,
    build_incident_timeline,
    build_narrative_handoff_packet,
    build_operator_summary,
)
from role_aware_dashboard_toolkit.runs import build_run
from role_aware_dashboard_toolkit.team_ops import build_signoff_record


@pytest.mark.parametrize("status", VALID_INCIDENT_STATUSES)
@pytest.mark.parametrize("severity", VALID_INCIDENT_SEVERITIES)
@pytest.mark.parametrize("signed_off", [False, True])
@pytest.mark.parametrize("case_state", ["open", "closed"])
def test_governance_actions_respect_incident_lifecycle_and_approval_coverage(
    status, severity, signed_off, case_state,
):
    incident = build_incident_record(
        "run_a", "Synthetic incident", incident_id="incident_a", status=status,
        severity=severity,
    )
    case = build_case_record(
        "Synthetic case", linked_incident_ids=["incident_a"], state=case_state,
    )
    signoffs = [
        build_signoff_record("run_a", "approved", role=role)
        for role in ("Approver", "Admin")
    ] if signed_off else []

    result = evaluate_case_governance(case, incidents=[incident], signoffs=signoffs)

    blocked = set(result["blocked_actions"])
    allowed = set(result["allowed_next_actions"])
    assert not blocked & allowed
    unresolved = status != "closed"
    missing_approvals = bool(result["approval_requirements"]["missing_roles"])
    assert ("close_case" in blocked) is (unresolved or missing_approvals)
    assert ("mitigate_incident" in allowed) is unresolved
    checks = {check["check_id"]: check for check in result["policy_checks"]}
    expected_gate = (
        "fail" if unresolved and severity == "critical" else
        "warn" if unresolved and severity == "high" else "pass"
    )
    assert checks["incident_severity_gate"]["result"] == expected_gate
    expected_closure = "warn" if case_state == "closed" and unresolved else "pass"
    assert checks["closure_consistency"]["result"] == expected_closure


@pytest.mark.parametrize("state", VALID_GOVERNANCE_STATES)
@pytest.mark.parametrize("missing_approval", [False, True])
@pytest.mark.parametrize("unresolved", [False, True])
def test_action_helpers_never_recommend_an_action_they_block(
    state, missing_approval, unresolved,
):
    requirements = {"missing_roles": ["Approver"] if missing_approval else []}
    incidents = [build_incident_record("run_a", "Synthetic incident")] if unresolved else []
    kwargs = {"approval_requirements": requirements, "unresolved_incidents": incidents}

    blocked = set(blocked_actions_for_governance(state, **kwargs))
    allowed = set(allowed_actions_for_governance(state, has_decisions=True, **kwargs))

    assert not blocked & allowed
    assert ("close_case" in allowed) is (
        state == "admissible" and not missing_approval and not unresolved
    )
    assert {"add_evidence", "link_case_record", "review_decision"} <= allowed


@pytest.mark.parametrize("status", VALID_INCIDENT_STATUSES)
@pytest.mark.parametrize("severity", VALID_INCIDENT_SEVERITIES)
def test_timeline_and_handoff_preserve_incident_status_and_open_count(status, severity):
    run = build_run({}, run_id="run_a")
    incident = build_incident_record(
        run["run_id"], "Synthetic incident", status=status, severity=severity,
    )
    before = deepcopy(incident)

    timeline = build_incident_timeline(run, incidents=[incident])
    event = next(item for item in timeline["events"] if item["event_type"] == "incident")
    summary = build_operator_summary(run, timeline=timeline, incidents=[incident])
    handoff = build_narrative_handoff_packet(run, timeline=timeline, incidents=[incident])

    assert event["refs"]["incident_status"] == status
    expected_open = int(status != "closed")
    assert timeline["summary"]["open_incident_count"] == expected_open
    assert summary["open_incident_count"] == expected_open
    assert handoff["summary"]["open_incident_count"] == expected_open
    assert incident == before


def test_mixed_incident_statuses_have_the_same_open_count_in_timeline_and_summary():
    run = build_run({}, run_id="run_a")
    incidents = [
        build_incident_record(run["run_id"], f"Synthetic {status}", status=status)
        for status in VALID_INCIDENT_STATUSES
    ]
    timeline = build_incident_timeline(run, incidents=incidents)
    summary = build_operator_summary(run, timeline=timeline, incidents=incidents)

    assert timeline["summary"]["incident_count"] == 4
    assert timeline["summary"]["open_incident_count"] == summary["open_incident_count"] == 3
