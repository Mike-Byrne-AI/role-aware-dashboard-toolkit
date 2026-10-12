"""Review conclusions must follow recorded evidence rather than timestamp spelling."""
from copy import deepcopy

import pytest

from role_aware_dashboard_toolkit.caseboard import build_case_record, summarize_caseboard
from role_aware_dashboard_toolkit.case_store import FileCaseStore, InMemoryCaseStore
from role_aware_dashboard_toolkit.decisions import build_decision_case, derive_decision_state, sync_decision_case
from role_aware_dashboard_toolkit.decision_store import FileDecisionStore, InMemoryDecisionStore
from role_aware_dashboard_toolkit.governance import build_governance_record, derive_approval_requirements, evaluate_case_governance
from role_aware_dashboard_toolkit.governance_store import FileGovernanceStore, InMemoryGovernanceStore
from role_aware_dashboard_toolkit.operator_memory import build_incident_timeline, build_operator_note, build_operator_summary
from role_aware_dashboard_toolkit.operator_memory_store import FileOperatorMemoryStore, InMemoryOperatorMemoryStore
from role_aware_dashboard_toolkit.runs import append_checkpoint, build_run
from role_aware_dashboard_toolkit.team_ops import build_handoff_summary, build_review_assignment, build_signoff_record, build_team_comment, summarize_team_ops
from role_aware_dashboard_toolkit.team_store import FileTeamStore, InMemoryTeamStore


OLDER = "2026-10-12T10:00:00+02:00"
NEWER = "2026-10-12T09:00:00+00:00"


def _signoff(decision, ts, *, actor="alice", role="Approver", run_id="run", checkpoint_id="cp", assignment_id=""):
    return {
        **build_signoff_record(run_id, decision, actor=actor, role=role,
                              checkpoint_id=checkpoint_id, assignment_id=assignment_id),
        "ts": ts,
    }


def test_rejected_checkpoint_remains_blocking_through_decision_and_governance():
    run = append_checkpoint(build_run({}, run_id="run"), {}, approval_state="rejected")
    decision = build_decision_case(run)

    assert decision["state"] == "rejected"
    assert any(item["kind"] == "rejected" for item in decision["blockers"])
    case = build_case_record("Review", linked_run_ids=["run"])
    governance = evaluate_case_governance(case, decisions=[decision])
    assert governance["state"] == "blocked"
    assert "apply_live_changes" in governance["blocked_actions"]
    assert derive_decision_state(approval_state="rejected", signoffs=[_signoff("approved", NEWER)]) == "rejected"


@pytest.mark.parametrize("approval", ["approved", "proposed"])
def test_completed_assignments_do_not_request_another_review(approval):
    assignments = [build_review_assignment("run", status="completed")]
    assert derive_decision_state(approval_state=approval, assignments=assignments) == approval


def test_rejected_checkpoint_transition_does_not_attribute_rejection_to_approval_signoff():
    run = append_checkpoint(build_run({}, run_id="run"), {})
    decision = build_decision_case(run)
    run = append_checkpoint(run, {}, approval_state="rejected")
    updated = sync_decision_case(decision, run=run, signoffs=[_signoff("approved", NEWER)])
    assert updated["state"] == "rejected"
    assert updated["last_event_type"] == "approval_synced"
    assert updated["history"][-1]["reason"] == "Approval state moved decision to rejected."


@pytest.mark.parametrize("approval, expected_state", [("rejected", "blocked"), ("frozen", "blocked"), ("replay_only", "replay_only")])
def test_governance_retains_checkpoint_restrictions_in_legacy_and_closed_decisions(approval, expected_state):
    run = append_checkpoint(build_run({}, run_id="run"), {}, approval_state=approval)
    decision = build_decision_case(run)
    case = build_case_record("Review", linked_run_ids=["run"])
    legacy = {**decision, "state": "proposed", "blockers": []}
    closed = sync_decision_case(decision, run=run, handoffs=[build_handoff_summary(run, status="closed")])
    assert closed["state"] == "closed"
    for record in (legacy, closed):
        governance = evaluate_case_governance(case, decisions=[record])
        assert governance["state"] == expected_state
        assert "apply_live_changes" in governance["blocked_actions"]


@pytest.mark.parametrize("newer_timestamp", [NEWER, "2026-10-12T09:00:00Z", "2026-10-12T09:00:00"])
def test_latest_signoff_uses_chronological_order(newer_timestamp):
    records = [_signoff("rejected", newer_timestamp), _signoff("approved", OLDER)]
    original = deepcopy(records)
    assert derive_decision_state(signoffs=records) == "rejected"
    assert summarize_team_ops(signoffs=records)["latest_signoff_decision"] == "rejected"
    handoff = build_handoff_summary({"run_id": "run"}, signoffs=records)
    assert handoff["summary"]["recent_signoffs"][0]["decision"] == "rejected"
    assert records == original


@pytest.mark.parametrize("file_backed", [False, True])
def test_team_and_memory_stores_order_offset_timestamps(tmp_path, file_backed):
    team = FileTeamStore(str(tmp_path / "team")) if file_backed else InMemoryTeamStore()
    memory = FileOperatorMemoryStore(str(tmp_path / "memory")) if file_backed else InMemoryOperatorMemoryStore()
    for body, ts in (("newer", NEWER), ("older", OLDER)):
        team.save_comment({**build_team_comment(body, run_id="run"), "ts": ts})
        memory.save_note({**build_operator_note(body, run_id="run"), "ts": ts})
    assert [row["body"] for row in team.list_comments("run")] == ["older", "newer"]
    assert [row["body"] for row in memory.list_notes("run")] == ["older", "newer"]


@pytest.mark.parametrize("file_backed", [False, True])
def test_decision_store_and_operator_summary_choose_latest_snapshot(tmp_path, file_backed):
    store = FileDecisionStore(str(tmp_path / "decisions")) if file_backed else InMemoryDecisionStore()
    run = build_run({}, run_id="run")
    approved = {**build_decision_case(run, decision_id="approved"), "state": "approved", "updated_at": OLDER}
    rejected = {**build_decision_case(run, decision_id="rejected"), "state": "rejected", "updated_at": NEWER}
    store.save(rejected)
    store.save(approved)
    rows = store.list_by_run("run")
    assert rows[-1]["state"] == "rejected"
    summary = build_operator_summary(run, timeline={"events": []}, decisions=[rejected, approved])
    assert summary["latest_decision_state"] == "rejected"


@pytest.mark.parametrize("file_backed", [False, True])
def test_case_and_governance_stores_order_latest_snapshots(tmp_path, file_backed):
    cases = FileCaseStore(str(tmp_path / "cases")) if file_backed else InMemoryCaseStore()
    governance = FileGovernanceStore(str(tmp_path / "governance")) if file_backed else InMemoryGovernanceStore()
    records = []
    for name, ts in (("newer", NEWER), ("older", OLDER)):
        case = {**build_case_record(name, case_id=name), "updated_at": ts}
        cases.save(case)
        governance.save({**build_governance_record(case, governance_id=name), "updated_at": ts})
        records.append(case)
    assert cases.list_cases()[-1]["case_id"] == "newer"
    assert governance.list_records()[-1]["governance_id"] == "newer"
    assert summarize_caseboard(records)["latest_case"]["case_id"] == "newer"


def test_undated_records_are_retained_with_stable_tie_order():
    store = InMemoryTeamStore()
    for identifier, ts in (("z", "invalid"), ("dated", NEWER), ("a", "")):
        store.save_comment({**build_team_comment(identifier, run_id="run", comment_id=identifier), "ts": ts})
    assert [row["comment_id"] for row in store.list_comments("run")] == ["dated", "a", "z"]


def test_incident_timeline_truncates_after_chronological_sort():
    notes = [
        {**build_operator_note("newer", run_id="run"), "ts": NEWER},
        {**build_operator_note("older", run_id="run"), "ts": OLDER},
    ]
    timeline = build_incident_timeline({"run_id": "run"}, notes=notes, max_items=1)
    assert timeline["events"][0]["detail"] == "newer"


def test_approval_coverage_supersedes_same_reviewer_in_same_scope():
    records = [_signoff("approved", OLDER), _signoff("rejected", NEWER)]
    original = deepcopy(records)
    for supplied in (records, list(reversed(records))):
        coverage = derive_approval_requirements("high", signoffs=supplied)
        assert coverage["missing_roles"] == ["Approver"]
        assert not coverage["is_satisfied"]
    assert records == original
    assert derive_approval_requirements("high", signoffs=[_signoff("rejected", OLDER), _signoff("approved", NEWER)])["is_satisfied"]


@pytest.mark.parametrize("changed_field, changed_value", [("actor", "bob"), ("run_id", "other"), ("checkpoint_id", "other")])
def test_approval_coverage_keeps_distinct_reviewers_and_scopes(changed_field, changed_value):
    rejection = _signoff("rejected", NEWER, **{changed_field: changed_value})
    coverage = derive_approval_requirements("high", signoffs=[_signoff("approved", OLDER), rejection])
    assert coverage["is_satisfied"]


def test_role_changes_and_assignment_metadata_do_not_preserve_old_approval():
    for rejection in (
        _signoff("rejected", NEWER, role="Admin"),
        _signoff("rejected", NEWER, assignment_id="another-assignment"),
    ):
        assert not derive_approval_requirements("high", signoffs=[_signoff("approved", OLDER), rejection])["is_satisfied"]


def test_anonymous_signoffs_supersede_within_role_and_scope():
    records = [_signoff("approved", OLDER, actor=""), _signoff("rejected", NEWER, actor="")]
    assert not derive_approval_requirements("high", signoffs=records)["is_satisfied"]
    records[-1]["role"] = "Admin"
    assert derive_approval_requirements("high", signoffs=records)["is_satisfied"]


def test_current_acknowledgement_retains_existing_positive_coverage_contract():
    assert derive_approval_requirements("high", signoffs=[_signoff("acknowledged", NEWER)])["is_satisfied"]


def test_uncertain_role_change_does_not_credit_both_roles():
    records = [_signoff("approved", NEWER), _signoff("approved", NEWER, role="Admin")]
    for supplied in (records, list(reversed(records))):
        assert derive_approval_requirements("critical", signoffs=supplied)["missing_roles"] == ["Approver", "Admin"]


@pytest.mark.parametrize("positive_ts, negative_ts", [(NEWER, NEWER), (NEWER, ""), ("invalid", NEWER), ("invalid", "")])
@pytest.mark.parametrize("negative", ["rejected", "changes_requested"])
def test_unresolved_signoff_time_cannot_restore_positive_coverage(positive_ts, negative_ts, negative):
    records = [_signoff("approved", positive_ts), _signoff(negative, negative_ts)]
    for supplied in (records, list(reversed(records))):
        assert not derive_approval_requirements("high", signoffs=supplied)["is_satisfied"]
