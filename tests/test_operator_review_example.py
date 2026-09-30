"""Behavior proofs for the synthetic operator workflow and actual Streamlit controls."""
from copy import deepcopy
from pathlib import Path

import pytest

import role_aware_dashboard_toolkit as radt
from examples.operator_review.workflow import (
    ReviewSession,
    build_evidence_packet,
    build_roles,
    capture_candidate,
    record_review,
    simulate_metrics,
    start_baseline,
)

APP = Path(__file__).resolve().parents[1] / "examples" / "operator_review" / "app.py"
RESOURCE_KEY = "_operator_review_session"


def context(role="Operator", *, writable=True):
    definition = radt.get_role(role, build_roles())
    return radt.make_security_context(role, definition.perms, controls_writable=writable)


def initial_state(session):
    state = {}
    session.registry.ensure_defaults(state)
    return state


def candidate_session():
    session = ReviewSession()
    state = initial_state(session)
    start_baseline(session, state, context())
    state["model_tier"] = "Thorough"
    capture_candidate(session, state, context())
    return session, state


def test_simulation_is_deterministic_and_baseline_is_a_detached_saved_profile():
    session = ReviewSession()
    state = initial_state(session)
    assert simulate_metrics(state) == {"quality_score": 85.0, "latency_ms": 979.6, "cost_per_100_requests": 0.17}
    assert simulate_metrics(state) == simulate_metrics(deepcopy(state))
    run = start_baseline(session, state, context())
    state["response_limit"] = 2048
    saved = session.profiles.load(run["source_profile_id"])
    checkpoint = session.current_run()["checkpoints"][0]
    assert saved["values"]["response_limit"] == 512
    assert checkpoint["controls"] == saved["values"]
    assert checkpoint["telemetry_slice"]["labels"]["measurement_kind"] == "simulated"
    assert checkpoint["telemetry_slice"]["units"]["latency_ms"] == "ms"
    assert checkpoint["telemetry_slice"]["ts"]


@pytest.mark.parametrize("decision,approval", [
    ("approved", "approved"), ("changes_requested", "proposed"), ("rejected", "rejected"),
])
def test_review_targets_recorded_candidate_and_completion_never_implies_approval(decision, approval):
    session, state = candidate_session()
    captured = deepcopy(session.current_run()["checkpoints"][-1])
    state["model_tier"] = "Economy"
    run = record_review(session, context("Approver"), decision=decision,
                        actor="Demo reviewer", reason="Quality tradeoff reviewed.")
    assert run["status"] == "completed"
    assert run["outcome"] == decision
    assert run["checkpoints"][-1]["controls"] == captured["controls"]
    assert run["checkpoints"][-1]["telemetry_slice"] == captured["telemetry_slice"]
    assert run["checkpoints"][-1]["approval_state"] == approval
    packet = build_evidence_packet(session, context("Approver"))
    restored = radt.load_packet_json(radt.export_packet_json(packet))
    review = restored["meta"]["operator_review"]
    assert review["signoffs"][0]["checkpoint_id"] == captured["checkpoint_id"]
    assert review["signoffs"][0]["decision"] == decision
    assert review["assignments"][0]["status"] == "completed"
    assert review["handoff"]["summary"]["latest_signoff_decision"] == decision
    assert "no model calls" in review["simulation"]
    with pytest.raises(ValueError, match="Capture a candidate"):
        record_review(session, context("Approver"), decision="approved", actor="Again", reason="Duplicate")
    assert len(session.team.list_signoffs(run["run_id"])) == 1


def test_sequence_and_required_review_explanation_fail_without_mutating_records():
    session = ReviewSession()
    state = initial_state(session)
    with pytest.raises(ValueError, match="Start a baseline"):
        capture_candidate(session, state, context())
    start_baseline(session, state, context())
    before = session.current_run()
    with pytest.raises(ValueError, match="Change at least one"):
        capture_candidate(session, state, context())
    assert session.current_run() == before
    state["model_tier"] = "Thorough"
    capture_candidate(session, state, context())
    before = session.current_run()
    with pytest.raises(ValueError, match="reviewer name and a reason"):
        record_review(session, context("Approver"), decision="approved", actor="Demo", reason="  ")
    assert session.current_run() == before
    assert session.team.list_signoffs() == []
    assert session.team.list_handoffs() == []


@pytest.mark.parametrize("role,writable", [("Viewer", True), ("Operator", False), ("Approver", False)])
def test_workflow_functions_recheck_authority_and_freeze_before_writing(role, writable):
    denied = context(role, writable=writable)
    session = ReviewSession()
    state = initial_state(session)
    with pytest.raises(PermissionError):
        start_baseline(session, state, denied)
    assert session.profiles.list_ids() == []
    assert session.runs.list_ids() == []
    start_baseline(session, state, context())
    before = session.current_run()
    state["model_tier"] = "Thorough"
    with pytest.raises(PermissionError):
        capture_candidate(session, state, denied)
    assert session.current_run() == before
    assert session.team.list_assignments() == []
    capture_candidate(session, state, context())
    before = session.current_run()
    with pytest.raises(PermissionError):
        record_review(session, denied, decision="approved", actor="Demo", reason="Denied")
    assert session.current_run() == before
    assert session.team.list_signoffs() == []
    assert session.team.list_handoffs() == []


def test_operator_cannot_signoff_and_frozen_authorized_reader_can_export():
    session, _ = candidate_session()
    with pytest.raises(PermissionError):
        record_review(session, context(), decision="approved", actor="Operator", reason="Denied")
    with pytest.raises(PermissionError):
        build_evidence_packet(session, context("Viewer"))
    packet = build_evidence_packet(session, context("Approver", writable=False))
    assert packet["payload"]["status"] == "active"
    assert packet["meta"]["operator_review"]["signoffs"] == []


@pytest.mark.parametrize("permission", [False, None])
def test_signoff_permissions_cannot_bypass_missing_team_visibility(permission):
    session, _ = candidate_session()
    denied = context("Approver")
    if permission is None:
        denied.perms.pop("can_view_team_ops")
    else:
        denied.perms["can_view_team_ops"] = permission
    before = session.current_run()
    with pytest.raises(PermissionError):
        record_review(session, denied, decision="approved", actor="Hidden reviewer", reason="Hidden reason")
    assert session.current_run() == before
    assert session.team.list_signoffs() == []
    assert session.team.list_handoffs() == []


@pytest.fixture
def app():
    AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
    at = AppTest.from_file(str(APP), default_timeout=15).run()
    healthy(at)
    return at


def healthy(at):
    assert not at.exception, [item.message for item in at.exception]
    assert not at.error, [item.value for item in at.error]


def test_real_ui_baseline_candidate_comparison_review_and_export(app):
    assert any("no model calls" in item.value for item in app.info)
    app.button(key="review_start").click().run()
    healthy(app)
    assert app.button(key="review_start").disabled
    app.selectbox(key="model_tier").select("Thorough").run()
    app.button(key="review_capture").click().run()
    healthy(app)
    session = app.session_state[RESOURCE_KEY]
    assert len(session.current_run()["checkpoints"]) == 2
    comparison = app.table[0].value
    latency = comparison[comparison["Metric"] == "latency_ms"].iloc[0]
    assert latency["Change"] == pytest.approx(350.0)
    assert latency["Unit"] == "ms"
    app.selectbox(key="_radt_role").select("Approver").run()
    healthy(app)
    assert app.selectbox(key="_radt_read_only_control__model_tier").disabled
    app.text_input(key="review_actor").input("Demo reviewer")
    app.text_area(key="review_reason").input("The quality gain is worth the simulated cost.")
    app.selectbox(key="review_decision").select("approved")
    app.button(key="review_signoff").click().run()
    healthy(app)
    run = session.current_run()
    assert run["outcome"] == "approved"
    assert app.button(key="review_signoff").disabled
    assert len(app.get("download_button")) == 2
    assert session.team.list_signoffs(run["run_id"])[0]["reason"] == "The quality gain is worth the simulated cost."


def test_baseline_profile_restore_changes_live_controls_without_rewriting_candidate(app):
    app.button(key="review_start").click().run()
    session = app.session_state[RESOURCE_KEY]
    profile_id = session.current_run()["source_profile_id"]
    assert profile_id in app.selectbox(key="_radt_profile_choice").options
    app.selectbox(key="model_tier").select("Thorough").run()
    app.button(key="review_capture").click().run()
    captured = deepcopy(session.current_run())
    app.selectbox(key="_radt_profile_choice").select(profile_id).run()
    app.button(key="_radt_profile_load").click().run()
    healthy(app)
    assert app.selectbox(key="model_tier").value == "Balanced"
    assert session.current_run() == captured


@pytest.mark.parametrize("save_review", [False, True])
def test_switching_to_viewer_hides_retained_review_inputs_and_result(app, save_review):
    app.button(key="review_start").click().run()
    app.selectbox(key="model_tier").select("Thorough").run()
    app.button(key="review_capture").click().run()
    app.selectbox(key="_radt_role").select("Approver").run()
    app.text_input(key="review_actor").input("Private reviewer 736")
    app.text_area(key="review_reason").input("Private review note 918")
    app.run()
    if save_review:
        app.button(key="review_signoff").click().run()
    healthy(app)
    session = app.session_state[RESOURCE_KEY]
    before_run = session.current_run()
    before_signoffs = session.team.list_signoffs()
    app.selectbox(key="_radt_role").select("Viewer").run()
    healthy(app)
    assert not {"review_actor", "review_reason", "review_decision", "review_signoff"}.intersection(
        item.key for kind in ("text_input", "text_area", "selectbox", "button") for item in app.get(kind)
    )
    visible_text = "\n".join(
        str(item.value) for kind in ("caption", "markdown", "success", "info", "warning", "json", "text")
        for item in app.get(kind)
    )
    assert "Private reviewer 736" not in visible_text
    assert "Private review note 918" not in visible_text
    assert "Review recorded:" not in visible_text
    assert len(app.table) >= 1
    assert not app.get("download_button")
    assert session.current_run() == before_run
    assert session.team.list_signoffs() == before_signoffs


def test_new_baseline_clears_previous_review_form(app):
    app.button(key="review_start").click().run()
    app.selectbox(key="model_tier").select("Thorough").run()
    app.button(key="review_capture").click().run()
    app.text_input(key="review_actor").input("Previous reviewer")
    app.text_area(key="review_reason").input("Previous review reason")
    app.selectbox(key="review_decision").select("rejected")
    app.button(key="review_signoff").click().run()
    old_id = app.session_state[RESOURCE_KEY].current_run_id
    app.button(key="review_start").click().run()
    app.selectbox(key="model_tier").select("Economy").run()
    app.button(key="review_capture").click().run()
    healthy(app)
    assert app.session_state[RESOURCE_KEY].current_run_id != old_id
    assert app.text_input(key="review_actor").value == ""
    assert app.text_area(key="review_reason").value == ""
    assert app.selectbox(key="review_decision").value == "approved"


def test_forged_review_click_cannot_bypass_team_visibility(app, monkeypatch):
    import streamlit as st
    from examples.operator_review import workflow

    app.button(key="review_start").click().run()
    app.selectbox(key="model_tier").select("Thorough").run()
    app.button(key="review_capture").click().run()
    roles = build_roles()
    roles["Blind approver"] = radt.RoleDef(
        "Blind approver", {**radt.get_role("Approver").perms, "can_view_team_ops": False},
    )
    monkeypatch.setattr(workflow, "build_roles", lambda: roles)
    app.run()
    app.selectbox(key="_radt_role").select("Blind approver").run()
    session = app.session_state[RESOURCE_KEY]
    before = session.current_run()
    original = st.button

    def forged_button(*args, **kwargs):
        clicked = original(*args, **kwargs)
        return True if kwargs.get("key") == "review_signoff" else clicked

    monkeypatch.setattr(st, "button", forged_button)
    app.run()
    healthy(app)
    assert "review_signoff" not in {button.key for button in app.button}
    assert session.current_run() == before
    assert session.team.list_signoffs() == []
    assert session.team.list_handoffs() == []


def test_ui_forged_click_cannot_bypass_viewer_or_freeze(app, monkeypatch):
    import streamlit as st

    app.selectbox(key="_radt_role").select("Viewer").run()
    healthy(app)
    assert app.button(key="review_start").disabled
    original = st.button

    def forged_button(*args, **kwargs):
        clicked = original(*args, **kwargs)
        return True if kwargs.get("key") == "review_start" else clicked

    with monkeypatch.context() as patch:
        patch.setattr(st, "button", forged_button)
        app.run()
        healthy(app)
    assert app.session_state[RESOURCE_KEY].runs.list_ids() == []
    assert any("do not permit" in item.value for item in app.warning)
    app.selectbox(key="_radt_role").select("Admin").run()
    app.toggle(key="_radt_writable").set_value(False).run()
    assert app.button(key="review_start").disabled
    with monkeypatch.context() as patch:
        patch.setattr(st, "button", forged_button)
        app.run()
        healthy(app)
    assert app.session_state[RESOURCE_KEY].runs.list_ids() == []
