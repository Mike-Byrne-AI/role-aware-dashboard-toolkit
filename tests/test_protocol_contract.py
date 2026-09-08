import json

import pytest

from role_aware_dashboard_toolkit import (
    build_audit_slice_packet,
    build_checkpoint_packet,
    build_compare_packet,
    build_ledger_packet,
    build_packet,
    build_run_packet,
    export_packet_json,
    extract_packet_payload,
    load_packet_json,
)
from role_aware_dashboard_toolkit._json_safety import strict_json_loads
from role_aware_dashboard_toolkit.packet_core import PACKET_SCHEMA_VERSION, VALID_PACKET_TYPES
from role_aware_dashboard_toolkit.validators import validate_packet


def _record(record_id: str) -> dict:
    return {"schema_version": 1, "id": record_id}


@pytest.mark.parametrize(
    ("packet", "packet_type"),
    [
        (build_run_packet({"schema_version": 1, "run_id": "run-1"}), "run"),
        (
            build_checkpoint_packet(
                {"schema_version": 1, "checkpoint_id": "checkpoint-1"},
                run_id="run-1",
            ),
            "checkpoint",
        ),
        (build_audit_slice_packet([{"type": "control_change"}]), "audit_slice"),
        (
            build_compare_packet(
                diff_type="dashboard",
                source_ids=["left", "right"],
                diff={"queue_depth": {"from": 1, "to": 2}},
            ),
            "compare",
        ),
        (build_ledger_packet({"schema_version": 1, "run_id": "run-1"}), "ledger"),
    ],
)
def test_builtin_packets_validate_and_round_trip(packet, packet_type):
    assert packet["schema_version"] == PACKET_SCHEMA_VERSION
    assert packet["packet_type"] == packet_type
    assert validate_packet(packet)["ok"] is True
    loaded = load_packet_json(export_packet_json(packet))
    assert loaded == json.loads(export_packet_json(packet))
    assert extract_packet_payload(loaded) == loaded["payload"]


def test_extension_packet_requires_x_prefix_and_schema_version():
    packet = build_packet("x_acme_status", _record("status-1"))
    result = validate_packet(packet)
    assert result["ok"] is True
    assert result["warnings"]

    with pytest.raises(ValueError, match="Custom packet types"):
        build_packet("acme_status", _record("status-1"))


@pytest.mark.parametrize(
    "packet_type",
    ["", "UPPER", "../escape", "x-hyphen", "1starts_with_number"],
)
def test_packet_type_syntax_fails_closed(packet_type):
    with pytest.raises(ValueError, match="packet_type"):
        build_packet(packet_type, _record("bad"))


def test_packet_registry_has_no_product_types():
    assert set(VALID_PACKET_TYPES) == {
        "profile",
        "run",
        "checkpoint",
        "audit_slice",
        "compare",
        "replay",
        "ledger",
        "narrative_handoff",
    }


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_packet_json_rejects_non_finite_numbers_on_export_and_load(value):
    packet = build_packet(
        "x_acme_status",
        {"schema_version": 1, "score": value},
    )

    with pytest.raises(ValueError, match="Out of range float values"):
        export_packet_json(packet)

    permissive_json = json.dumps(packet)
    with pytest.raises(ValueError, match="non-finite numeric constant"):
        load_packet_json(permissive_json)


def test_packet_json_rejects_float_overflow_on_load():
    packet = build_packet(
        "x_acme_status",
        {"schema_version": 1, "score": "OVERFLOW"},
    )
    raw = json.dumps(packet).replace('"OVERFLOW"', "1e9999")

    with pytest.raises(ValueError, match="outside the finite float range"):
        load_packet_json(raw)


def test_strict_json_loader_preserves_standard_numeric_types():
    loaded = strict_json_loads(
        '{"count": 3, "fraction": 1.25, "exponent": 2e2}'
    )

    assert loaded == {"count": 3, "fraction": 1.25, "exponent": 200.0}
    assert type(loaded["count"]) is int
    assert type(loaded["fraction"]) is float
    assert type(loaded["exponent"]) is float
