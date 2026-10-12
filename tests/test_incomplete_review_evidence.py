"""Native reviews must not turn failed or denied reads into favorable evidence."""
from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

import role_aware_dashboard_toolkit as radt
from role_aware_dashboard_toolkit._evidence_reads import EvidenceUnavailable, read_evidence, read_records
from role_aware_dashboard_toolkit.access import AccessPolicy, Identity, InMemoryAccessStore
from role_aware_dashboard_toolkit.case_store import FileCaseStore, InMemoryCaseStore
from role_aware_dashboard_toolkit.caseboard import build_case_record
from role_aware_dashboard_toolkit.decision_store import FileDecisionStore
from role_aware_dashboard_toolkit.decisions import build_decision_case_from_run
from role_aware_dashboard_toolkit.governance_store import InMemoryGovernanceStore
from role_aware_dashboard_toolkit.operator_memory import build_incident_record
from role_aware_dashboard_toolkit.operator_memory_store import FileOperatorMemoryStore
from role_aware_dashboard_toolkit.runbook_panels_parts.review_models import build_governance_panel_preview
from role_aware_dashboard_toolkit.security import RoleDef, SecurityContext, get_role
from role_aware_dashboard_toolkit.team_ops import build_signoff_record, build_team_comment
from role_aware_dashboard_toolkit.team_store import FileTeamStore


def _render(host, panel):
    import streamlit as st
    from role_aware_dashboard_toolkit.runbook_panels_parts.caseboard import _render_caseboard_panel
    from role_aware_dashboard_toolkit.runbook_panels_parts.decisions import _render_decision_panel
    from role_aware_dashboard_toolkit.runbook_panels_parts.governance import _render_governance_panel
    from role_aware_dashboard_toolkit.runbook_panels_parts.operator_memory import _render_operator_memory_panel
    from role_aware_dashboard_toolkit.runbook_panels_parts.team_ops import _render_team_ops_panel, _render_team_ops_sidebar

    if panel == "governance":
        _render_governance_panel(st, host.config, host.ctx, [host.run])
    elif panel == "decision":
        _render_decision_panel(st, host.config, host.ctx, host.run, host.checkpoint)
    elif panel == "memory":
        _render_operator_memory_panel(st, host.config, host.ctx, host.run, host.checkpoint)
    elif panel == "caseboard":
        _render_caseboard_panel(st, host.config, host.ctx, [host.run], host.run)
    elif panel == "team":
        _render_team_ops_panel(st, host.config, host.ctx, host.run)
    elif panel == "handoff":
        _render_team_ops_sidebar(st, host.config, host.ctx, host.run)


def _healthy(app):
    assert not app.exception, [item.message for item in app.exception]
    return app


def _app(host, panel):
    AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
    return _healthy(AppTest.from_function(_render, args=(host, panel), default_timeout=15).run())


def _displayed(app):
    return [json.loads(item.value) for item in app.json]


@pytest.fixture
def host(tmp_path):
    roles = {"Review": RoleDef("Review", dict(get_role("Admin").perms))}
    grants = InMemoryAccessStore(allowed_roles=("Review",))
    policy = AccessPolicy(
        lambda: Identity("https://synthetic.invalid", "synthetic-reviewer", time.time() + 300),
        grants, b"synthetic-review-tests-key-32bytes",
    )
    principal = policy.identify()
    grants.replace_grants(principal, ("Review",))
    grants.compare_and_set_freeze(False, 0, principal)
    ctx = SecurityContext(
        role="Review", perms=dict(roles["Review"].perms), authenticated=True,
        user_id=principal, session_id="a" * 32,
        _authorize=lambda permission, write: policy.authorize(
            principal, "Review", permission, roles, write=write
        ),
    )
    run = radt.append_checkpoint(radt.build_run({}, run_id="synthetic-run"), {}, approval_state="approved")
    case = build_case_record("Synthetic case", case_id="synthetic-case", linked_run_ids=[run["run_id"]])
    config = SimpleNamespace(
        case_store=InMemoryCaseStore(), governance_store=InMemoryGovernanceStore(),
        decision_store=FileDecisionStore(str(tmp_path / "decisions")),
        team_store=FileTeamStore(str(tmp_path / "team")),
        operator_memory_store=FileOperatorMemoryStore(str(tmp_path / "memory")),
        audit=radt.AuditLog(),
    )
    config.case_store.save(case)
    return SimpleNamespace(config=config, ctx=ctx, roles=roles, policy=policy, run=run,
                           checkpoint=run["checkpoints"][-1], case=case)


@pytest.mark.parametrize("source", ["decision", "incident"])
def test_governance_corrupt_partial_evidence_blocks_stale_save_and_recovers(host, source):
    if source == "decision":
        record = build_decision_case_from_run(host.run, checkpoint=host.checkpoint)
        record["state"] = "rejected"
        store = host.config.decision_store
        path = Path(store.save(record))
        # A surviving row must not make the failed collection look complete.
        valid = build_decision_case_from_run(host.run, checkpoint=host.checkpoint)
        store.save(valid)
    else:
        store = host.config.operator_memory_store
        path = Path(store.save_incident(build_incident_record(
            host.run["run_id"], "Synthetic incident", severity="critical", status="open",
        )))
        store.save_incident(build_incident_record(host.run["run_id"], "Another incident", status="closed"))
    original = path.read_bytes()
    app = _app(host, "governance")
    assert _displayed(app)[0]["state"] == "blocked"
    path.write_text("{synthetic-corrupt", encoding="utf-8")
    _healthy(app.button(key="_radt_governance_save::synthetic-case").click().run())
    assert store.read_errors and app.warning and not app.json and not app.button
    assert host.config.governance_store.list_records() == []
    path.write_bytes(original)
    _healthy(app.run())
    assert not app.warning and _displayed(app)[0]["state"] == "blocked"
    assert store.read_errors  # Historical failures do not prevent recovery.
    _healthy(app.button(key="_radt_governance_save::synthetic-case").click().run())
    assert host.config.governance_store.list_records()[0]["state"] == "blocked"


def test_unreadable_rejected_signoff_cannot_overwrite_decision_as_approved(host):
    signoff = build_signoff_record(host.run["run_id"], "rejected", checkpoint_id=host.checkpoint["checkpoint_id"])
    path = Path(host.config.team_store.save_signoff(signoff))
    record = build_decision_case_from_run(host.run, checkpoint=host.checkpoint, signoffs=[signoff])
    saved_path = Path(host.config.decision_store.save(record))
    saved_bytes = saved_path.read_bytes()
    app = _app(host, "decision")
    assert _displayed(app)[0]["state"] == "rejected"
    path.write_text("{synthetic-corrupt", encoding="utf-8")
    key = f"_radt_decision_save::{host.run['run_id']}::{host.checkpoint['checkpoint_id']}"
    _healthy(app.button(key=key).click().run())
    assert app.warning and not app.json and not app.button
    assert saved_path.read_bytes() == saved_bytes


@pytest.mark.parametrize("panel", ["memory", "caseboard", "team"])
def test_sibling_panels_warn_instead_of_showing_empty_evidence(host, panel):
    if panel == "team":
        path = Path(host.config.team_store.save_signoff(build_signoff_record(host.run["run_id"], "rejected")))
    else:
        path = Path(host.config.operator_memory_store.save_incident(build_incident_record(
            host.run["run_id"], "Synthetic open incident",
        )))
    app = _app(host, panel)
    assert app.json
    path.write_text("{synthetic-corrupt", encoding="utf-8")
    _healthy(app.run())
    assert app.warning and not app.json and not app.button
    assert not any("No cross-run cases" in item.value for item in app.caption)


def test_corrupt_case_list_does_not_claim_no_cases_or_offer_creation(host, tmp_path):
    host.config.case_store = FileCaseStore(str(tmp_path / "cases"))
    path = Path(host.config.case_store.save(host.case))
    path.write_text("{synthetic-corrupt", encoding="utf-8")
    app = _app(host, "caseboard")
    assert app.warning and not app.json and not app.button
    assert host.config.case_store.read_errors


def test_narrative_stale_save_cannot_claim_zero_incidents(host):
    store = host.config.operator_memory_store
    path = Path(store.save_incident(build_incident_record(host.run["run_id"], "Synthetic incident")))
    app = _app(host, "memory")
    path.write_text("{synthetic-corrupt", encoding="utf-8")
    _healthy(app.button(key=f"_radt_save_narrative_{host.run['run_id']}").click().run())
    assert app.warning and not app.json
    assert store.list_narratives(host.run["run_id"]) == []


def test_handoff_creation_does_not_persist_incomplete_team_evidence(host):
    store = host.config.team_store
    path = Path(store.save_signoff(build_signoff_record(host.run["run_id"], "rejected")))
    app = _app(host, "handoff")
    path.write_text("{synthetic-corrupt", encoding="utf-8")
    _healthy(app.button(key="_radt_handoff_btn").click().run())
    assert app.warning and store.list_handoffs(host.run["run_id"]) == []
    assert not any(event["type"] == "run_handoff" for event in host.config.audit.all_events())


@pytest.mark.parametrize("permission", ["can_view_team_ops", "can_manage_runs"])
def test_handoff_dependency_read_revocation_blocks_save_and_audit(host, monkeypatch, permission):
    original = host.config.team_store.list_signoffs

    def revoking_read(*args, **kwargs):
        records = original(*args, **kwargs)
        host.roles["Review"].perms[permission] = False
        return records

    monkeypatch.setattr(host.config.team_store, "list_signoffs", revoking_read)
    app = _app(host, "handoff")
    _healthy(app.button(key="_radt_handoff_btn").click().run())
    assert app.warning and not host.config.team_store.list_handoffs(host.run["run_id"])
    assert not any(event["type"] == "run_handoff" for event in host.config.audit.all_events())


def test_team_final_read_revocation_prevents_prior_comment_disclosure(host, monkeypatch):
    host.config.team_store.save_comment(build_team_comment(
        "synthetic-private-comment", run_id=host.run["run_id"],
    ))

    def revoking_read(*args, **kwargs):
        host.roles["Review"].perms["can_view_team_ops"] = False
        return []

    monkeypatch.setattr(host.config.team_store, "list_handoffs", revoking_read)
    app = _app(host, "team")
    assert app.warning and not app.json
    assert "synthetic-private-comment" not in repr(app.warning)


@pytest.mark.parametrize("panel", ["decision", "governance", "memory"])
def test_cross_source_final_read_revocation_blocks_derived_view(host, monkeypatch, panel):
    store = host.config.governance_store if panel == "governance" else host.config.team_store
    method = "list_records" if panel == "governance" else "list_handoffs"
    original = getattr(store, method)

    def revoking_read(*args, **kwargs):
        records = original(*args, **kwargs)
        host.roles["Review"].perms["can_view_decisions"] = False
        return records

    monkeypatch.setattr(store, method, revoking_read)
    app = _app(host, panel)
    assert app.warning and not app.json and not app.button


def test_governance_denied_decisions_are_neither_read_nor_replaced_with_empty(host, monkeypatch):
    host.roles["Review"].perms["can_view_decisions"] = False
    calls = []
    monkeypatch.setattr(host.config.decision_store, "list_by_run", lambda *a, **k: calls.append("read"))
    app = _app(host, "governance")
    assert not calls and app.warning and not app.json and not app.button
    assert host.config.governance_store.list_records() == []


def test_governance_keeps_decision_boundary_after_optional_source_is_removed(host, monkeypatch):
    host.config.decision_store = None
    host.roles["Review"].perms["can_view_decisions"] = False
    reads = []
    monkeypatch.setattr(host.config.case_store, "list_cases", lambda: reads.append("case"))
    monkeypatch.setattr(host.config.governance_store, "list_by_case", lambda *a: reads.append("governance"))
    app = _app(host, "governance")
    assert app.warning and not app.json and not reads
    with pytest.raises(EvidenceUnavailable):
        build_governance_panel_preview(host.config, host.case, actor="", role="Review", ctx=host.ctx)
    assert not reads


def test_semantically_invalid_json_is_incomplete_evidence(host):
    record = build_decision_case_from_run(host.run, checkpoint=host.checkpoint)
    record["state"] = "unknown-private-marker"
    host.config.decision_store.save(record)
    app = _app(host, "governance")
    assert app.warning and not app.json
    assert "unknown-private-marker" not in repr(app.warning)
    assert not host.config.decision_store.read_errors  # JSON itself was valid.


def test_read_result_distinguishes_optional_empty_failed_and_denied(host):
    store = host.config.decision_store
    assert read_evidence(None, "unused", record_type="decision").status == "unconfigured"
    assert read_evidence(store, "list_by_run", host.run["run_id"], record_type="decision").status == "complete"
    host.roles["Review"].perms["can_view_decisions"] = False
    result = read_evidence(store, "list_by_run", host.run["run_id"], record_type="decision",
                           ctx=host.ctx, permission="can_view_decisions")
    assert result.status == "denied"
    with pytest.raises(EvidenceUnavailable):
        result.require_complete()
    with pytest.raises(EvidenceUnavailable, match="^Review evidence is unavailable or incomplete[.]$"):
        read_records(SimpleNamespace(), "missing-method", record_type="decision")


def test_optional_unconfigured_evidence_preserves_supported_empty_preview(host):
    host.config.decision_store = None
    host.config.operator_memory_store = None
    host.config.team_store = None
    app = _app(host, "governance")
    assert not app.warning and _displayed(app)[0]["state"] == "admissible"


def test_decision_reference_is_resolved_without_a_run_reference(host):
    decision = build_decision_case_from_run(host.run, checkpoint=host.checkpoint)
    decision["state"] = "rejected"
    host.config.decision_store.save(decision)
    host.case["linked_run_ids"] = []
    host.case["linked_decision_ids"] = [decision["decision_id"]]
    host.config.case_store.save(host.case)
    app = _app(host, "governance")
    assert not app.warning and _displayed(app)[0]["state"] == "blocked"


@pytest.mark.parametrize("field,store_name", [
    ("linked_decision_ids", "decision_store"),
    ("linked_incident_ids", "operator_memory_store"),
    ("linked_note_ids", "operator_memory_store"),
    ("linked_narrative_ids", "operator_memory_store"),
])
@pytest.mark.parametrize("configured", [True, False])
def test_explicit_reference_missing_or_unconfigured_never_counts_as_evidence(host, field, store_name, configured):
    host.case[field] = ["synthetic-missing-reference"]
    host.config.case_store.save(host.case)
    if not configured:
        setattr(host.config, store_name, None)
    app = _app(host, "governance")
    assert app.warning and not app.json and not app.button


@pytest.mark.parametrize("configured", [True, False])
def test_missing_linked_run_does_not_count_as_evidence(host, configured):
    host.case["linked_run_ids"] = ["synthetic-missing-run"]
    host.config.case_store.save(host.case)
    if configured:
        host.config.run_store = radt.InMemoryRunStore()
    app = _app(host, "governance")
    assert app.warning and not app.json and not app.button


@pytest.mark.parametrize("linked_run", [False, True])
@pytest.mark.parametrize("configured", [False, True])
def test_checkpoint_references_resolve_before_approval(host, linked_run, configured):
    if not linked_run:
        host.case["linked_run_ids"] = []
    host.case["linked_checkpoint_ids"] = ["synthetic-missing-checkpoint"]
    host.config.case_store.save(host.case)
    if configured:
        host.config.run_store = radt.InMemoryRunStore()
        host.config.run_store.save(host.run)
    app = _app(host, "governance")
    assert app.warning and not app.json and not app.button
    host.case["linked_checkpoint_ids"] = [host.checkpoint["checkpoint_id"]]
    host.config.case_store.save(host.case)
    _healthy(app.run())
    assert not app.warning and app.json


def test_checkpoint_reference_does_not_trust_stale_ui_run(host):
    host.case["linked_checkpoint_ids"] = [host.checkpoint["checkpoint_id"]]
    host.config.case_store.save(host.case)
    host.config.run_store = radt.InMemoryRunStore()
    host.config.run_store.save(radt.build_run({}, run_id=host.run["run_id"]))
    app = _app(host, "governance")
    assert app.warning and not app.json and not app.button


def _checkpoint_only_case_with_closed_incident(host):
    incident = build_incident_record(host.run["run_id"], "Resolved incident", severity="low", status="closed")
    host.config.operator_memory_store.save_incident(incident)
    host.case["linked_run_ids"] = []
    host.case["linked_checkpoint_ids"] = [host.checkpoint["checkpoint_id"]]
    host.case["linked_incident_ids"] = [incident["incident_id"]]
    host.config.case_store.save(host.case)


def test_checkpoint_only_scope_includes_rejected_decision_before_save(host):
    _checkpoint_only_case_with_closed_incident(host)
    decision = build_decision_case_from_run(host.run, checkpoint=host.checkpoint)
    decision["state"] = "rejected"
    host.config.decision_store.save(decision)
    app = _app(host, "governance")
    assert not app.warning and _displayed(app)[0]["state"] == "blocked"
    _healthy(app.button(key="_radt_governance_save::synthetic-case").click().run())
    assert host.config.governance_store.list_records()[0]["state"] == "blocked"
    decision["state"] = "approved"
    host.config.decision_store.save(decision)
    _healthy(app.run())
    assert not app.warning and _displayed(app)[0]["state"] == "admissible"
    _healthy(app.button(key="_radt_governance_save::synthetic-case").click().run())
    assert host.config.governance_store.list_records()[0]["state"] == "admissible"


def test_checkpoint_only_scope_does_not_borrow_unlinked_decisions_or_signoffs(host):
    _checkpoint_only_case_with_closed_incident(host)
    host.run = radt.append_checkpoint(host.run, {}, approval_state="rejected")
    other_checkpoint = host.run["checkpoints"][-1]
    rejected = build_decision_case_from_run(host.run, checkpoint=other_checkpoint)
    host.config.decision_store.save(rejected)
    host.config.team_store.save_signoff(build_signoff_record(
        host.run["run_id"], "approved", checkpoint_id=other_checkpoint["checkpoint_id"], role="Approver",
    ))
    host.case["priority"] = "high"
    host.config.case_store.save(host.case)
    app = _app(host, "governance")
    assert not app.warning and _displayed(app)[0]["state"] == "escalated"
    preview = next(item for item in _displayed(app) if isinstance(item, dict) and "approval_requirements" in item)
    assert preview["approval_requirements"]["missing_roles"] == ["Approver"]
    assert next(item for item in preview["policy_checks"] if item["check_id"] == "decision_health")["result"] == "pass"
    host.config.team_store.save_signoff(build_signoff_record(
        host.run["run_id"], "approved", checkpoint_id=host.checkpoint["checkpoint_id"], role="Approver",
    ))
    _healthy(app.run())
    assert not app.warning
    preview = next(item for item in _displayed(app) if isinstance(item, dict) and "approval_requirements" in item)
    assert preview["approval_requirements"]["missing_roles"] == []
    assert next(item for item in preview["policy_checks"] if item["check_id"] == "approval_coverage")["result"] == "pass"


def test_adding_explicit_approved_decision_cannot_hide_linked_run_rejection(host):
    rejected = build_decision_case_from_run(host.run, checkpoint=host.checkpoint)
    rejected["state"] = "rejected"
    approved = build_decision_case_from_run(host.run, checkpoint=host.checkpoint)
    host.config.decision_store.save(rejected)
    host.config.decision_store.save(approved)
    host.case["linked_decision_ids"] = [approved["decision_id"]]
    host.config.case_store.save(host.case)
    app = _app(host, "governance")
    assert not app.warning and _displayed(app)[0]["state"] == "blocked"
    _healthy(app.button(key="_radt_governance_save::synthetic-case").click().run())
    assert host.config.governance_store.list_records()[0]["state"] == "blocked"


@pytest.mark.parametrize("field", [
    "linked_run_ids", "linked_checkpoint_ids", "linked_decision_ids", "linked_incident_ids", "linked_note_ids",
])
def test_malformed_reference_is_incomplete_evidence_with_safe_warning(host, field):
    host.case[field] = [{"private": "synthetic-invalid-reference"}]
    host.config.case_store.save(host.case)
    app = _app(host, "governance")
    assert app.warning and not app.json and not app.button
    assert "synthetic-invalid-reference" not in repr(app.warning)


def test_configured_run_source_takes_precedence_over_stale_ui_run(host):
    host.config.run_store = radt.InMemoryRunStore()
    app = _app(host, "governance")
    assert app.warning and not app.json
    host.config.run_store.save(host.run)
    _healthy(app.run())
    assert not app.warning and _displayed(app)[0]["state"] == "admissible"


def test_store_exception_is_failed_without_exposing_original_exception():
    def broken():
        raise PermissionError("synthetic-private-source-path-and-token")

    result = read_evidence(SimpleNamespace(list_records=broken), "list_records", record_type="decision")
    assert result.status == "failed"
    assert "synthetic-private" not in repr(result)


def test_governance_ui_ignores_unrelated_incident_until_explicitly_linked(host):
    incident = build_incident_record("unrelated-run", "Unrelated incident", severity="critical")
    host.config.operator_memory_store.save_incident(incident)
    app = _app(host, "governance")
    assert not app.warning and _displayed(app)[0]["state"] == "admissible"
    _healthy(app.button(key="_radt_governance_save::synthetic-case").click().run())
    assert host.config.governance_store.list_records()[0]["state"] == "admissible"

    host.case["linked_incident_ids"] = [incident["incident_id"]]
    host.config.case_store.save(host.case)
    _healthy(app.run())
    assert not app.warning and _displayed(app)[0]["state"] == "blocked"
    _healthy(app.button(key="_radt_governance_save::synthetic-case").click().run())
    assert host.config.governance_store.list_records()[0]["state"] == "blocked"
