"""Shared values cannot make packet redaction or encoding walk without bound."""
from __future__ import annotations

import time

import pytest

from role_aware_dashboard_toolkit import build_packet, export_packet_json
from role_aware_dashboard_toolkit import packet_core


def _doubling(levels):
    """Each level lists the previous one twice: ``levels`` containers, 2**levels paths."""
    value = {"leaf": 1}
    for _ in range(levels):
        value = [value, value]
    return value


def test_shared_value_expansion_beyond_the_bound_is_refused(monkeypatch):
    # raising=False lets this run against a checker without the bound, which fails it.
    monkeypatch.setattr(packet_core, "MAX_SHARED_VALUE_EXPANSION", 1_000, raising=False)

    with pytest.raises(ValueError, match="shared"):
        build_packet("x_probe", {"schema_version": 1, "n": _doubling(12)})


def test_a_reference_bomb_is_refused_at_once():
    # 60 lists, 2**60 paths: walking them would never finish.
    started = time.perf_counter()
    with pytest.raises(ValueError, match="shared"):
        build_packet("x_probe", {"schema_version": 1, "n": _doubling(60)})
    with pytest.raises(ValueError, match="shared"):
        export_packet_json({"schema_version": 1, "packet_type": "x_probe", "packet_id": "p",
                            "exported_at": "t", "payload_schema_version": 1,
                            "payload": {"schema_version": 1, "n": _doubling(60)}})
    assert time.perf_counter() - started < 1.0


def test_ordinary_sharing_and_large_trees_are_accepted():
    shared = {"mode": "fast"}
    packet = build_packet("x_probe", {"schema_version": 1, "uses": [shared] * 100})
    assert packet["payload"]["uses"] == [shared] * 100

    tree = {"schema_version": 1, "rows": [{"i": index} for index in range(20_000)]}
    assert len(build_packet("x_probe", tree)["payload"]["rows"]) == 20_000
