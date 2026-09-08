from __future__ import annotations

from role_aware_dashboard_toolkit.controls import ControlRegistry
from role_aware_dashboard_toolkit.replay import (
    apply_replay_packet,
    build_replay_packet_from_audit,
    build_replay_packet_from_checkpoint,
)
from role_aware_dashboard_toolkit.sensitive_values import REDACTED_SECRET


def test_checkpoint_replay_packet_deeply_detaches_control_values() -> None:
    checkpoint = {
        "checkpoint_id": "checkpoint-1",
        "controls": {"mode": {"labels": ["safe"]}},
    }

    packet = build_replay_packet_from_checkpoint(checkpoint)
    checkpoint["controls"]["mode"]["labels"].append("fast")

    assert packet["controls"] == {"mode": {"labels": ["safe"]}}

    packet["controls"]["mode"]["labels"].append("review")

    assert checkpoint["controls"] == {"mode": {"labels": ["safe", "fast"]}}


def test_audit_replay_packet_deeply_detaches_new_values() -> None:
    events = [
        {
            "type": "control_change",
            "key": "policy",
            "new": {"checks": ["lint"]},
        }
    ]

    packet = build_replay_packet_from_audit(events)
    events[0]["new"]["checks"].append("test")

    assert packet["controls"] == {"policy": {"checks": ["lint"]}}


def test_apply_replay_ignores_sensitive_redacted_and_unknown_controls() -> None:
    registry = ControlRegistry()
    registry.register("Mode", kind="text", key="mode", default="safe")
    registry.register("Status", kind="text", key="status", default="ready")
    registry.register(
        "API Token",
        kind="text",
        key="api_token",
        default="",
        sensitive=True,
    )
    session_state = {
        "mode": "safe",
        "status": "ready",
        "api_token": "live-secret",
    }
    packet = {
        "controls": {
            "mode": "fast",
            "status": REDACTED_SECRET,
            "api_token": "captured-secret",
            "unknown": "unexpected",
        }
    }

    result = apply_replay_packet(packet, registry, session_state)

    assert result == {
        "applied": 1,
        "corrected": 0,
        "touched_keys": ["mode"],
    }
    assert session_state == {
        "mode": "fast",
        "status": "ready",
        "api_token": "live-secret",
    }


def test_audit_redaction_marker_cannot_overwrite_live_secret() -> None:
    registry = ControlRegistry()
    registry.register(
        "API Token",
        kind="text",
        key="api_token",
        default="",
        sensitive=True,
    )
    events = [
        {
            "type": "control_change",
            "key": "api_token",
            "new": REDACTED_SECRET,
        },
        {
            "type": "control_change",
            "key": "unknown",
            "new": "value",
        },
    ]
    session_state = {"api_token": "live-secret"}

    result = apply_replay_packet(
        build_replay_packet_from_audit(events),
        registry,
        session_state,
    )

    assert result == {"applied": 0, "corrected": 0, "touched_keys": []}
    assert session_state == {"api_token": "live-secret"}


def test_applied_replay_value_does_not_alias_packet_value() -> None:
    old_value = {"checks": ["lint"]}
    new_value = {"checks": ["lint", "test"]}
    registry = ControlRegistry()
    registry.register(
        "Policy",
        kind="select",
        key="policy",
        default=old_value,
        options=[old_value, new_value],
    )
    packet = {"controls": {"policy": new_value}}
    session_state = {"policy": old_value}

    result = apply_replay_packet(packet, registry, session_state)
    packet["controls"]["policy"]["checks"].append("package")

    assert result["touched_keys"] == ["policy"]
    assert session_state["policy"] == {"checks": ["lint", "test"]}


def test_apply_replay_does_not_invoke_arbitrary_value_equality() -> None:
    class HostileEquality(str):
        def __eq__(self, _other):
            raise AssertionError("replay sentinel checks must not invoke value equality")

    registry = ControlRegistry()
    registry.register("Mode", kind="text", key="mode", default="safe")
    session_state = {"mode": "safe"}

    result = apply_replay_packet(
        {"controls": {"mode": HostileEquality("fast")}},
        registry,
        session_state,
    )

    assert result == {"applied": 1, "corrected": 0, "touched_keys": ["mode"]}
    assert str.__eq__(session_state["mode"], "fast") is True
