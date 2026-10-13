"""Deep or cyclic packets are refused with ValueError, never RecursionError."""
from __future__ import annotations

import json

import pytest

from role_aware_dashboard_toolkit import build_packet, export_packet_json, load_packet_json
from role_aware_dashboard_toolkit import packet_core

LIMIT = 100


def _nested(levels):
    """Return a value of ``levels`` nested mappings (a scalar for 0)."""
    value = 1
    for _ in range(levels):
        value = {"a": value}
    return value


def _envelope(payload):
    return {
        "schema_version": 1, "packet_type": "x_probe", "packet_id": "p1",
        "exported_at": "2026-01-01T00:00:00+00:00", "payload_schema_version": 1,
        "payload": payload,
    }


def test_the_documented_limit_is_100_levels():
    assert getattr(packet_core, "MAX_PACKET_NESTING_DEPTH", None) == LIMIT


def test_json_too_deep_for_the_decoder_raises_value_error():
    raw = json.dumps(_envelope({"schema_version": 1}))
    raw = raw.replace('"schema_version": 1}', '"schema_version": 1, "n": ' + "[" * 100_000 + "]" * 100_000 + "}", 1)

    with pytest.raises(ValueError, match="nest"):
        load_packet_json(raw)


def test_json_deeper_than_the_limit_raises_value_error():
    # Envelope (1) + payload (2) + 99 more levels = 101 levels.
    raw = json.dumps(_envelope({"schema_version": 1, "n": _nested(99)}))

    with pytest.raises(ValueError, match="nest"):
        load_packet_json(raw)


def test_packet_at_the_limit_round_trips():
    # Envelope (1) + payload (2) + 98 more levels = 100 levels.
    packet = build_packet("x_probe", {"schema_version": 1, "n": _nested(98)})

    restored = load_packet_json(export_packet_json(packet))

    assert restored["payload"]["n"] == _nested(98)


@pytest.mark.parametrize("levels", [99, 5_000])
def test_export_refuses_a_packet_deeper_than_the_limit(levels):
    with pytest.raises(ValueError, match="nest"):
        export_packet_json(_envelope({"schema_version": 1, "n": _nested(levels)}))


@pytest.mark.parametrize("levels", [99, 5_000])
def test_build_refuses_a_payload_deeper_than_the_limit(levels):
    with pytest.raises(ValueError, match="nest"):
        build_packet("x_probe", {"schema_version": 1, "n": _nested(levels)})


def test_build_refuses_deep_metadata():
    with pytest.raises(ValueError, match="nest"):
        build_packet("x_probe", {"schema_version": 1}, meta={"n": _nested(99)})


def test_build_and_export_refuse_a_cyclic_payload():
    payload = {"schema_version": 1, "items": []}
    payload["items"].append(payload)

    with pytest.raises(ValueError, match="nest"):
        build_packet("x_probe", payload)
    with pytest.raises(ValueError, match="nest"):
        export_packet_json(_envelope(payload))
