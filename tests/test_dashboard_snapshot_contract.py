from role_aware_dashboard_toolkit.checkpoints import (
    DASHBOARD_SNAPSHOT_SCHEMA_VERSION,
    build_dashboard_snapshot,
)
from role_aware_dashboard_toolkit.compare import compare_dashboard_snapshots

import pytest


def test_build_dashboard_snapshot_captures_dashboard_state_shape():
    snapshot = build_dashboard_snapshot(
        controls={"temperature": 0.7, "mode": "safe"},
        snapshot_id="dash_left",
        label="left",
        groups={"Generation": ["temperature"], "Safety": ["mode"]},
        role="Operator",
        controls_writable=True,
        available_roles=["Admin", "Operator", "Viewer"],
        active_profile_id="baseline",
        available_profiles=["baseline", "release"],
        audit_events=[{"type": "control_change", "ts": "2026-05-27T22:00:00Z"}],
        plugin_metadata=[{"name": "health-summary", "version": "1.0.0", "capabilities": ["panel"]}],
    )

    assert snapshot["schema_version"] == DASHBOARD_SNAPSHOT_SCHEMA_VERSION
    assert snapshot["snapshot_type"] == "dashboard_state"
    assert snapshot["snapshot_id"] == "dash_left"
    assert snapshot["controls"]["temperature"] == 0.7
    assert snapshot["groups"] == [
        {"group": "Generation", "keys": ["temperature"]},
        {"group": "Safety", "keys": ["mode"]},
    ]
    assert snapshot["security"]["active_role"] == "Operator"
    assert snapshot["security"]["controls_writable"] is True
    assert snapshot["profiles"]["active_profile_id"] == "baseline"
    assert snapshot["audit_summary"]["event_count"] == 1
    assert snapshot["plugins"]["count"] == 1


def test_build_dashboard_snapshot_redacts_controls_and_keeps_restore_payload_safe():
    snapshot = build_dashboard_snapshot(
        controls={"api_key": "secret", "temperature": 0.5},
        role="Admin",
        controls_writable=False,
        active_profile_id="prod",
        redact_keys=["api_key"],
    )

    assert snapshot["controls"]["api_key"] == "[REDACTED]"
    assert snapshot["controls"]["temperature"] == 0.5
    assert snapshot["redaction"]["redacted_keys"] == ["api_key"]
    assert snapshot["restore_payload"]["controls"] == {"temperature": 0.5}
    assert snapshot["restore_payload"]["active_role"] == "Admin"
    assert snapshot["restore_payload"]["controls_writable"] is False
    assert snapshot["restore_payload"]["active_profile_id"] == "prod"


def test_compare_dashboard_snapshots_reports_control_and_state_deltas():
    left = build_dashboard_snapshot(
        controls={"temperature": 0.7, "api_key": "secret"},
        snapshot_id="left",
        role="Operator",
        controls_writable=True,
        active_profile_id="baseline",
        audit_events=[{"type": "control_change"}],
        plugin_metadata=[{"name": "health-summary"}],
        redact_keys=["api_key"],
    )
    right = build_dashboard_snapshot(
        controls={"temperature": 0.9, "api_key": "secret"},
        snapshot_id="right",
        role="Approver",
        controls_writable=False,
        active_profile_id="release-check",
        audit_events=[{"type": "control_change"}, {"type": "profile_load"}],
        plugin_metadata=[{"name": "health-summary"}, {"name": "ops-notes"}],
        redact_keys=["api_key"],
    )

    compare = compare_dashboard_snapshots(left, right)
    assert compare["left_snapshot_id"] == "left"
    assert compare["right_snapshot_id"] == "right"
    assert compare["control_diff"]["temperature"] == {"from": 0.7, "to": 0.9}
    assert compare["security_transition"]["role"] == {"from": "Operator", "to": "Approver"}
    assert compare["security_transition"]["controls_writable"] == {"from": True, "to": False}
    assert compare["profile_transition"]["active_profile_id"] == {"from": "baseline", "to": "release-check"}
    assert compare["plugin_diff"]["added"] == ["ops-notes"]
    assert compare["plugin_diff"]["removed"] == []
    assert compare["audit_event_delta"] == 1


def test_compare_dashboard_snapshots_keeps_empty_restore_controls_authoritative():
    left = build_dashboard_snapshot({"api_key": "same", "size": 1}, redact_keys=["api_key"])
    right = build_dashboard_snapshot({"api_key": "same"}, redact_keys=["api_key"])
    assert compare_dashboard_snapshots(left, right)["control_diff"] == {"size": {"from": 1, "to": None}}
    assert compare_dashboard_snapshots(right, left)["control_diff"] == {"size": {"from": None, "to": 1}}


@pytest.mark.parametrize("restore", [None, {}, {"controls": None}])
def test_compare_dashboard_snapshots_preserves_legacy_fallback(restore):
    left = {"controls": {"size": 1}, "restore_payload": restore}
    right = build_dashboard_snapshot({"size": 2})
    assert compare_dashboard_snapshots(left, right)["control_diff"] == {"size": {"from": 1, "to": 2}}
