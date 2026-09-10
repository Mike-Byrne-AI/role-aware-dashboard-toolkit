from types import SimpleNamespace

import pytest

import role_aware_dashboard_toolkit.dashboard as dashboard_module
from role_aware_dashboard_toolkit._ui_state import apply_pending_replay
from role_aware_dashboard_toolkit import ControlRegistry, InMemoryRunStore, append_checkpoint, build_run
from role_aware_dashboard_toolkit.dashboard import DashboardConfig
from role_aware_dashboard_toolkit.observability import ObservabilityConfig
from role_aware_dashboard_toolkit.operator_memory_store import InMemoryOperatorMemoryStore
from role_aware_dashboard_toolkit.runbook_panels import render_runbook_panel, render_runbook_sidebar
from role_aware_dashboard_toolkit.runbook_panels_parts import decisions as decision_panels
from role_aware_dashboard_toolkit.runbook_panels_parts.governance import (
    _render_governance_panel,
)
from role_aware_dashboard_toolkit.runbook_panels_parts.operator_memory import _render_operator_memory_panel
from role_aware_dashboard_toolkit.security import make_security_context
from role_aware_dashboard_toolkit.sidebar import SidebarResult
from role_aware_dashboard_toolkit.team_store import InMemoryTeamStore
from tests.test_governance_contract import (
    Config,
    FakeStreamlit,
    _seed_case,
)
from tests.test_runbook_contract import (
    _FakeStreamlit as RunbookStreamlit,
    _runbook_config,
)


class _DashboardStreamlit:
    def __init__(self):
        self.session_state = {}
        self.events = []

    def title(self, value):
        self.events.append(("title", str(value)))

    def caption(self, value):
        self.events.append(("caption", str(value)))

    def info(self, value):
        self.events.append(("info", str(value)))

    def warning(self, value):
        self.events.append(("warning", str(value)))


class _DefiantRunbookStreamlit(RunbookStreamlit):
    """Simulate an adapter that returns clicks even for disabled buttons."""

    def button(self, label, key=None, disabled=False, **kwargs):
        self.events.append(("button", str(label), str(key or ""), bool(disabled)))
        return True


def test_team_permission_does_not_imply_governance_visibility():
    config = Config()
    _seed_case(config)
    st = FakeStreamlit(save=True)
    ctx = make_security_context(
        "Custom",
        {"can_view_team_ops": True},
    )

    _render_governance_panel(st, config, ctx, runs=[])

    assert st.events == []
    assert config.governance_store.list_records() == []


def test_run_permission_does_not_imply_governance_management():
    config = Config()
    _seed_case(config)
    ctx = make_security_context(
        "Custom",
        {
            "can_view_governance": True,
            "can_manage_runs": True,
        },
    )

    _render_governance_panel(
        FakeStreamlit(save=True),
        config,
        ctx,
        runs=[],
    )

    assert config.governance_store.list_records() == []


def test_dashboard_auth_failure_stops_all_protected_rendering(monkeypatch):
    st = _DashboardStreamlit()
    failed_ctx = make_security_context(
        "Unauthenticated",
        {},
        controls_writable=False,
    )
    config = DashboardConfig()
    protected_calls = []

    monkeypatch.setattr(dashboard_module, "st", st)
    monkeypatch.setattr(
        dashboard_module,
        "render_sidebar",
        lambda _st, _config: SidebarResult(ctx=failed_ctx, plugin_errors=[]),
    )
    monkeypatch.setattr(
        dashboard_module,
        "render_groups",
        lambda *_args, **_kwargs: protected_calls.append("controls"),
    )
    monkeypatch.setattr(
        dashboard_module,
        "render_runbook_panel",
        lambda *_args, **_kwargs: protected_calls.append("runbook"),
    )
    monkeypatch.setattr(
        dashboard_module,
        "render_audit_panel",
        lambda *_args, **_kwargs: protected_calls.append("audit"),
    )
    monkeypatch.setattr(
        config.plugins,
        "render_panels",
        lambda *_args, **_kwargs: protected_calls.append("plugins") or [],
    )

    assert dashboard_module.render(config) == failed_ctx
    assert protected_calls == []
    assert st.events == []


def test_dashboard_metrics_permission_gates_controls_and_observability(monkeypatch):
    st = _DashboardStreamlit()
    denied_ctx = make_security_context("No metrics", {"can_view_metrics": False})
    config = DashboardConfig(
        observability=ObservabilityConfig(
            enabled=True,
            telemetry_hook=lambda: {"metrics": {"private": 1}},
        )
    )
    protected_calls = []

    monkeypatch.setattr(dashboard_module, "st", st)
    monkeypatch.setattr(
        dashboard_module,
        "render_sidebar",
        lambda _st, _config: SidebarResult(ctx=denied_ctx, plugin_errors=[]),
    )
    monkeypatch.setattr(
        dashboard_module,
        "render_groups",
        lambda *_args, **_kwargs: protected_calls.append("controls"),
    )
    monkeypatch.setattr(
        dashboard_module,
        "ObservabilityPanel",
        lambda *_args, **_kwargs: protected_calls.append("observability"),
    )
    monkeypatch.setattr(dashboard_module, "render_runbook_panel", lambda *_args: None)

    assert dashboard_module.render(config) == denied_ctx
    assert protected_calls == []
    assert "_radt_observability_history" not in st.session_state


def test_dashboard_metrics_permission_preserves_permitted_rendering(monkeypatch):
    st = _DashboardStreamlit()
    allowed_ctx = make_security_context("Metrics", {"can_view_metrics": True})
    config = DashboardConfig(
        observability=ObservabilityConfig(enabled=True),
    )
    protected_calls = []

    class _RecordingPanel:
        def __init__(self, *_args, **_kwargs):
            pass

        def render(self, _st):
            protected_calls.append("observability")

    monkeypatch.setattr(dashboard_module, "st", st)
    monkeypatch.setattr(
        dashboard_module,
        "render_sidebar",
        lambda _st, _config: SidebarResult(ctx=allowed_ctx, plugin_errors=[]),
    )
    monkeypatch.setattr(
        dashboard_module,
        "render_groups",
        lambda *_args, **_kwargs: protected_calls.append("controls"),
    )
    monkeypatch.setattr(dashboard_module, "ObservabilityPanel", _RecordingPanel)
    monkeypatch.setattr(dashboard_module, "render_runbook_panel", lambda *_args: None)

    assert dashboard_module.render(config) == allowed_ctx
    assert protected_calls == ["controls", "observability"]


def test_decision_visibility_denial_stops_preview_build(monkeypatch):
    preview_calls = []
    config = SimpleNamespace(decision_store=object())
    ctx = make_security_context(
        "Decision manager without view",
        {
            "can_view_decisions": False,
            "can_manage_decisions": True,
        },
    )

    monkeypatch.setattr(
        decision_panels,
        "build_decision_panel_preview",
        lambda *_args, **_kwargs: preview_calls.append("preview"),
    )

    decision_panels._render_decision_panel(
        SimpleNamespace(session_state={}),
        config,
        ctx,
        {"run_id": "private-run"},
        {"checkpoint_id": "private-checkpoint"},
    )

    assert preview_calls == []


def test_team_visibility_denial_stops_run_store_reads():
    class _DeniedRunStore:
        def list_ids(self):
            raise AssertionError("run store read crossed can_view_team_ops")

    config = SimpleNamespace(run_store=_DeniedRunStore())
    st = RunbookStreamlit()
    ctx = make_security_context(
        "Metrics without team context",
        {
            "can_view_metrics": True,
            "can_view_team_ops": False,
        },
    )

    render_runbook_sidebar(st, config, ctx)
    render_runbook_panel(st, config, ctx)

    assert st.events == []


def test_packet_export_denial_hides_all_runbook_packet_previews():
    registry = ControlRegistry()
    registry.register(
        "Mode",
        kind="select",
        key="mode",
        options=["safe", "fast"],
        default="safe",
    )
    store = InMemoryRunStore()
    run = build_run({"mode": "safe"}, run_id="private-run")
    run = append_checkpoint(run, {"mode": "fast"}, label="private-checkpoint")
    store.save(run)
    st = RunbookStreamlit(session_state={"_radt_selected_run_id": run["run_id"]})
    ctx = make_security_context(
        "Viewer",
        {
            "can_view_metrics": True,
            "can_view_team_ops": True,
            "can_export_packets": False,
            "can_replay_runs": False,
        },
    )

    render_runbook_panel(st, _runbook_config(store, registry=registry), ctx)

    expander_labels = [event[1] for event in st.events if event[0] == "expander"]
    subheader_labels = [event[1] for event in st.events if event[0] == "subheader"]
    assert "Protocol Preview" not in expander_labels
    assert "Checkpoint Packet" not in expander_labels
    assert "Replay Preview" not in subheader_labels


def test_packet_export_denial_hides_narrative_packet_and_blocks_save():
    memory_store = InMemoryOperatorMemoryStore()
    run = build_run({"mode": "safe"}, run_id="private-run")
    run = append_checkpoint(run, {"mode": "fast"}, label="private-checkpoint")
    checkpoint = run["checkpoints"][-1]
    config = _runbook_config(
        InMemoryRunStore(),
        operator_memory_store=memory_store,
    )
    st = RunbookStreamlit(
        button_returns={f"_radt_save_narrative_{run['run_id']}": True},
        session_state={"_radt_user_id": "viewer"},
    )
    ctx = make_security_context(
        "Packet denied",
        {
            "can_view_team_ops": True,
            "can_manage_runs": True,
            "can_export_packets": False,
        },
    )

    _render_operator_memory_panel(st, config, ctx, run, checkpoint)

    assert not any(
        event[0] == "expander" and event[1] == "Narrative handoff packet"
        for event in st.events
    )
    assert memory_store.list_narratives(run["run_id"]) == []


@pytest.mark.parametrize(
    ("can_view_metrics", "can_view_audit", "can_export_packets"),
    [
        (False, False, False),
        (False, False, True),
        (True, False, True),
        (False, True, True),
        (True, True, True),
    ],
)
def test_runbook_hides_checkpoint_metrics_and_audit_without_view_permissions(
    can_view_metrics, can_view_audit, can_export_packets,
):
    registry = ControlRegistry()
    registry.register(
        "Secret mode",
        kind="text",
        key="secret_mode",
        default="initial-secret",
    )
    store = InMemoryRunStore()
    run = build_run(
        {"secret_mode": "initial-secret"},
        run_id="private-run",
    )
    run = append_checkpoint(
        run,
        {"secret_mode": "checkpoint-secret"},
        label="checkpoint",
        audit_events=[{"detail": "audit-secret"}],
        telemetry={"private-metric": 42},
    )
    store.save(run)
    st = RunbookStreamlit(session_state={"_radt_selected_run_id": run["run_id"]})
    ctx = make_security_context(
        "Team metadata only",
        {
            "can_view_team_ops": True,
            "can_view_metrics": can_view_metrics,
            "can_view_audit": can_view_audit,
            "can_export_packets": can_export_packets,
        },
    )

    render_runbook_panel(st, _runbook_config(store, registry=registry), ctx)

    rendered = repr(st.events)
    can_export_run_evidence = can_export_packets and can_view_metrics and can_view_audit
    assert ("initial-secret" in rendered) is can_export_run_evidence
    assert ("checkpoint-secret" in rendered) is can_view_metrics
    assert ("private-metric" in rendered) is can_view_metrics
    assert ("audit-secret" in rendered) is can_view_audit
    expanders = [event[1] for event in st.events if event[0] == "expander"]
    subheaders = [event[1] for event in st.events if event[0] == "subheader"]
    assert ("Protocol Preview" in expanders) is can_export_run_evidence
    assert ("Checkpoint Packet" in expanders) is can_export_run_evidence
    assert ("Replay Preview" in subheaders) is (can_export_packets and can_view_metrics)


def test_nested_team_view_does_not_read_denied_decisions_metrics_or_audit():
    class _DeniedDecisionStore:
        def list_by_run(self, _run_id):
            raise AssertionError("decision store read crossed can_view_decisions")

    class _DeniedAudit:
        def recent(self, _limit):
            raise AssertionError("audit read crossed can_view_audit")

    memory_store = InMemoryOperatorMemoryStore()
    run = build_run({"mode": "safe"}, run_id="private-run")
    config = SimpleNamespace(
        operator_memory_store=memory_store,
        decision_store=_DeniedDecisionStore(),
        team_store=None,
        audit=_DeniedAudit(),
        timeline_title="Incident Timeline",
        version="test",
    )
    st = RunbookStreamlit(
        session_state={
            "_radt_observability_history": [
                {"metrics": {"private-metric": 42}},
            ]
        }
    )
    ctx = make_security_context(
        "Team only",
        {
            "can_view_team_ops": True,
            "can_view_decisions": False,
            "can_view_metrics": False,
            "can_view_audit": False,
            "can_export_packets": False,
        },
    )

    _render_operator_memory_panel(st, config, ctx, run, {})

    assert "private-metric" not in repr(st.events)


def test_disabled_runbook_buttons_are_not_an_authorization_boundary():
    registry = ControlRegistry()
    registry.register(
        "Mode",
        kind="select",
        key="mode",
        options=["safe", "fast"],
        default="safe",
    )
    run_store = InMemoryRunStore()
    run = build_run({"mode": "safe"}, run_id="active-run")
    run_store.save(run)
    team_store = InMemoryTeamStore()
    config = _runbook_config(
        run_store,
        registry=registry,
        team_store=team_store,
    )
    st = _DefiantRunbookStreamlit(
        session_state={
            "_radt_active_run_id": run["run_id"],
            "_radt_team_comment_body": "unauthorized",
            "_radt_review_title": "unauthorized",
        }
    )
    ctx = make_security_context(
        "Read only",
        {
            "can_view_team_ops": True,
            "can_manage_runs": False,
            "can_comment_runs": False,
            "can_assign_reviews": False,
            "can_signoff_runs": False,
        },
    )

    render_runbook_sidebar(st, config, ctx)

    unchanged = run_store.load(run["run_id"])
    assert unchanged["status"] == "active"
    assert unchanged["checkpoints"] == []
    assert team_store.list_comments(run["run_id"]) == []
    assert team_store.list_assignments(run["run_id"]) == []
    assert team_store.list_signoffs(run["run_id"]) == []
    assert team_store.list_handoffs(run["run_id"]) == []
    assert config.audit.all_events() == []


def test_frozen_dashboard_rejects_replay_even_if_disabled_button_returns_true():
    registry = ControlRegistry()
    registry.register(
        "Mode",
        kind="select",
        key="mode",
        options=["safe", "fast"],
        default="safe",
    )
    run_store = InMemoryRunStore()
    run = build_run({"mode": "safe"}, run_id="frozen-run")
    run = append_checkpoint(run, {"mode": "fast"}, label="checkpoint")
    run_store.save(run)
    config = _runbook_config(run_store, registry=registry)
    st = _DefiantRunbookStreamlit(
        session_state={
            "_radt_selected_run_id": run["run_id"],
            "mode": "safe",
        }
    )
    ctx = make_security_context(
        "Frozen operator",
        {
            "can_view_team_ops": True,
            "can_replay_runs": True,
            "can_export_packets": False,
        },
        controls_writable=False,
    )

    render_runbook_panel(st, config, ctx)

    replay_button = next(
        event
        for event in st.events
        if event[0] == "button" and event[2] == "_radt_checkpoint_replay_btn"
    )
    assert replay_button[3] is True
    assert st.session_state["mode"] == "safe"
    assert config.audit.all_events() == []


@pytest.mark.parametrize("can_admin_controls", [False, True])
def test_replay_preflights_every_control_permission_atomically(can_admin_controls):
    registry = ControlRegistry()
    registry.register("Mode", kind="text", key="mode", default="safe")
    registry.register(
        "Restricted",
        kind="text",
        key="restricted",
        default="initial",
        permission="can_admin_controls",
    )
    run = append_checkpoint(
        build_run({"mode": "safe", "restricted": "initial"}, run_id="mixed-run"),
        {"mode": "fast", "restricted": "updated"},
        label="checkpoint",
    )
    run_store = InMemoryRunStore()
    run_store.save(run)
    config = _runbook_config(run_store, registry=registry)
    st = RunbookStreamlit(
        button_returns={"_radt_checkpoint_replay_btn": True},
        session_state={"mode": "safe", "restricted": "initial"},
    )
    ctx = make_security_context(
        "Replay operator",
        {
            "can_view_team_ops": True,
            "can_replay_runs": True,
            "can_edit_controls": True,
            "can_admin_controls": can_admin_controls,
        },
    )

    render_runbook_panel(st, config, ctx)

    if can_admin_controls:
        assert st.session_state["mode"] == "safe"
        assert config.audit.all_events() == []
        apply_pending_replay(st, config, ctx)
        assert st.session_state["mode"] == "fast"
        assert st.session_state["restricted"] == "updated"
        assert [event["type"] for event in config.audit.all_events()] == ["checkpoint_replay"]
        assert ("rerun",) in st.events
    else:
        assert st.session_state["mode"] == "safe"
        assert st.session_state["restricted"] == "initial"
        assert config.audit.all_events() == []
        assert ("rerun",) not in st.events


def test_replay_preflights_changes_to_controls_outside_the_packet():
    registry = ControlRegistry()
    registry.register("Mode", kind="text", key="mode", default="safe")
    registry.register(
        "Restricted number",
        kind="number",
        key="restricted_number",
        default=0,
        min_value=0,
        max_value=10,
        permission="can_admin_controls",
    )
    run = append_checkpoint(
        build_run({"mode": "safe"}, run_id="sanitized-run"),
        {"mode": "fast"},
        label="checkpoint",
    )
    run_store = InMemoryRunStore()
    run_store.save(run)
    config = _runbook_config(run_store, registry=registry)
    st = RunbookStreamlit(
        button_returns={"_radt_checkpoint_replay_btn": True},
        session_state={"mode": "safe", "restricted_number": 100},
    )
    ctx = make_security_context(
        "Replay operator",
        {
            "can_view_team_ops": True,
            "can_replay_runs": True,
            "can_edit_controls": True,
            "can_admin_controls": False,
        },
    )

    render_runbook_panel(st, config, ctx)

    assert st.session_state["mode"] == "safe"
    assert st.session_state["restricted_number"] == 100
    assert config.audit.all_events() == []


def test_replay_permission_preflight_ignores_inert_packet_entries():
    registry = ControlRegistry()
    registry.register("Mode", kind="text", key="mode", default="safe")
    registry.register(
        "Redacted",
        kind="text",
        key="redacted",
        default="initial",
        permission="can_admin_controls",
    )
    registry.register(
        "Credential",
        kind="text",
        key="credential",
        default="",
        permission="can_admin_controls",
        sensitive=True,
    )
    run = append_checkpoint(
        build_run({"mode": "safe"}, run_id="inert-run"),
        {
            "mode": "fast",
            "redacted": "<redacted-secret>",
            "credential": "captured-secret",
            "unknown": "ignored",
        },
        label="checkpoint",
    )
    run_store = InMemoryRunStore()
    run_store.save(run)
    config = _runbook_config(run_store, registry=registry)
    st = RunbookStreamlit(
        button_returns={"_radt_checkpoint_replay_btn": True},
        session_state={"mode": "safe", "redacted": "initial", "credential": "live-secret"},
    )
    ctx = make_security_context(
        "Replay operator",
        {
            "can_view_team_ops": True,
            "can_replay_runs": True,
            "can_edit_controls": True,
            "can_admin_controls": False,
        },
    )

    render_runbook_panel(st, config, ctx)

    assert st.session_state["mode"] == "safe"
    assert config.audit.all_events() == []
    apply_pending_replay(st, config, ctx)
    assert st.session_state["mode"] == "fast"
    assert st.session_state["redacted"] == "initial"
    assert st.session_state["credential"] == "live-secret"
    assert "unknown" not in st.session_state
    assert [event["type"] for event in config.audit.all_events()] == ["checkpoint_replay"]
