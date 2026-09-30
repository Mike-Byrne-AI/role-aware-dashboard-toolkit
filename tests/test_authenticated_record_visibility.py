"""Native review records must not bypass live stored-control visibility."""
from __future__ import annotations

from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from role_aware_dashboard_toolkit import append_checkpoint, build_run
from role_aware_dashboard_toolkit.decision_store import InMemoryDecisionStore
from role_aware_dashboard_toolkit.decisions import build_decision_case_from_run
from role_aware_dashboard_toolkit.runbook_panels_parts.decisions import _render_decision_panel
from role_aware_dashboard_toolkit.runbook_panels_parts.team_ops import _render_team_ops_panel
from role_aware_dashboard_toolkit.security import SecurityContext
from role_aware_dashboard_toolkit.team_ops import build_handoff_summary
from role_aware_dashboard_toolkit.team_store import InMemoryTeamStore
from tests.test_runbook_contract import _FakeStreamlit


CONTROL_MARKER = "synthetic-stored-control-for-metrics-viewers"


def _records():
    run = append_checkpoint(
        build_run({"restricted_control": CONTROL_MARKER}, run_id="run_visibility"),
        {"restricted_control": CONTROL_MARKER}, label="Review checkpoint",
    )
    checkpoint = run["checkpoints"][-1]
    config = SimpleNamespace(
        team_store=InMemoryTeamStore(), decision_store=InMemoryDecisionStore(),
    )
    config.team_store.save_handoff(build_handoff_summary(run))
    config.decision_store.save(build_decision_case_from_run(run, checkpoint=checkpoint))
    return config, run, checkpoint


class _DetailStreamlit(_FakeStreamlit):
    def __init__(self, before_detail=None, **kwargs):
        super().__init__(**kwargs)
        self.before_detail = before_detail

    def expander(self, label, expanded=False):
        if label in {"Decision Case", "Latest handoff"} and self.before_detail:
            self.before_detail()
        return super().expander(label, expanded=expanded)


@pytest.mark.parametrize("panel", ["decision", "handoff"])
@pytest.mark.parametrize("permission", ["allowed", "denied_live", "denied_snapshot", "revoked_at_detail"])
def test_native_summary_controls_follow_live_metrics_permission_without_changing_records(panel, permission):
    config, run, checkpoint = _records()
    before = deepcopy((run, config.decision_store.list_by_run(run["run_id"]), config.team_store.list_handoffs()))
    current = {"metrics": permission != "denied_live"}
    checks = []

    def authorize(key, writing):
        checks.append((key, writing))
        return current["metrics"] if key == "can_view_metrics" else True

    ctx = SecurityContext(
        role="Review only", authenticated=True, user_id="a" * 64,
        perms={
            "can_view_team_ops": True, "can_view_decisions": True,
            "can_view_metrics": permission != "denied_snapshot",
        },
        _authorize=authorize,
    )

    def revoke_metrics():
        if permission == "revoked_at_detail":
            current["metrics"] = False

    st = _DetailStreamlit(before_detail=revoke_metrics)
    if panel == "decision":
        _render_decision_panel(st, config, ctx, run, checkpoint)
        record_id = "decision_id"
    else:
        _render_team_ops_panel(st, config, ctx, run)
        record_id = "handoff_id"
    displayed = [event[1] for event in st.events if event[0] == "json"]
    details = next(record for record in reversed(displayed) if record_id in record)

    assert (CONTROL_MARKER in json.dumps(displayed)) is (permission == "allowed")
    assert details["summary"]["run_status"] == run["status"]
    assert ("latest_controls" in details["summary"]) is (permission == "allowed")
    assert (run, config.decision_store.list_by_run(run["run_id"]), config.team_store.list_handoffs()) == before
    if permission != "denied_snapshot":
        assert ("can_view_metrics", False) in checks


def test_decision_display_redaction_preserves_authorized_saved_evidence():
    config, run, checkpoint = _records()
    ctx = SecurityContext(
        role="Decision manager", authenticated=True, user_id="b" * 64,
        perms={"can_view_decisions": True, "can_manage_decisions": True, "can_view_metrics": True},
        _authorize=lambda key, writing: key != "can_view_metrics",
    )
    key = f"_radt_decision_save::{run['run_id']}::{checkpoint['checkpoint_id']}"
    st = _DetailStreamlit(button_returns={key: True})

    _render_decision_panel(st, config, ctx, run, checkpoint)

    displayed = [event[1] for event in st.events if event[0] == "json"]
    assert CONTROL_MARKER not in json.dumps(displayed)
    assert any(event[0] == "toast" for event in st.events)
    saved = config.decision_store.list_by_run(run["run_id"])[-1]
    assert saved["summary"]["latest_controls"] == run["latest_controls"]
