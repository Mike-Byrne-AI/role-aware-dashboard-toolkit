"""Validation errors name fields and expected shapes, never the saved values."""
from __future__ import annotations

import pytest

from role_aware_dashboard_toolkit import build_run, build_run_packet
from role_aware_dashboard_toolkit.caseboard import build_case_record
from role_aware_dashboard_toolkit.validators import validate_packet, validate_record

CANARY = "/Users/alice/SECRET-CANARY-token"


def _run(**changes):
    run = build_run({}, run_id="run-1")
    run.update(changes)
    return run


def _case(**changes):
    case = build_case_record("Outage", case_id="case-1")
    case.update(changes)
    return case


def _errors_text(result):
    assert result["ok"] is False
    return "\n".join(result["errors"])


@pytest.mark.parametrize("bad", [CANARY, {"password": CANARY}, [CANARY], 7])
def test_invalid_enum_value_is_not_echoed(bad):
    text = _errors_text(validate_record("run", _run(status=bad)))

    assert "Invalid run status" in text
    assert "SECRET-CANARY" not in text and "alice" not in text
    assert "'status'" in text and "'active'" in text


def test_invalid_record_item_value_is_not_echoed():
    case = _case(history=[{"event_type": CANARY}])

    text = _errors_text(validate_record("case", case))

    assert "history[0] invalid event_type" in text
    assert "SECRET-CANARY" not in text and "alice" not in text


@pytest.mark.parametrize("bad", [CANARY, {"token": CANARY}, 1.5, True])
def test_unexpected_schema_version_is_not_echoed(bad):
    text = _errors_text(validate_record("run", _run(schema_version=bad)))

    assert "Unexpected schema_version for run" in text
    assert "SECRET-CANARY" not in text and "alice" not in text
    assert "expected 1" in text


def test_unexpected_integer_schema_version_is_named():
    text = _errors_text(validate_record("run", _run(schema_version=2)))

    assert "Unexpected schema_version for run: expected 1, found 2." in text


def test_oversized_integer_schema_version_reports_an_error_instead_of_raising():
    text = _errors_text(validate_record("run", _run(schema_version=10**5000)))

    assert "Unexpected schema_version for run: expected 1, found another integer." in text


def test_packet_payload_errors_do_not_echo_saved_values():
    packet = build_run_packet(_run())
    packet["payload"]["status"] = CANARY

    text = _errors_text(validate_packet(packet))

    assert "payload.Invalid run status" in text
    assert "SECRET-CANARY" not in text and "alice" not in text
