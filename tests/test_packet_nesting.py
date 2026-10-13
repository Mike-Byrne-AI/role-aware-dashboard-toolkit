"""Deep or cyclic packets are refused with ValueError, never RecursionError."""
from __future__ import annotations

import json

import pytest

from role_aware_dashboard_toolkit import build_packet, export_packet_json, load_packet_json
from role_aware_dashboard_toolkit import packet_core

LIMIT = 500
# Frames a host may already use when it calls the packet functions (a web
# framework or Streamlit script run sits well inside this).
HOST_STACK_FRAMES = 250


def _nested(levels, kind="dict"):
    """Return a value of ``levels`` nested mappings or lists (a scalar for 0)."""
    value = 1
    for _ in range(levels):
        value = {"a": value} if kind == "dict" else [value]
    return value


def _with_stack_in_use(frames, call):
    """Run ``call`` with ``frames`` Python frames already on the stack."""
    if frames <= 0:
        return call()
    return _with_stack_in_use(frames - 1, call)


def _envelope(payload):
    return {
        "schema_version": 1, "packet_type": "x_probe", "packet_id": "p1",
        "exported_at": "2026-01-01T00:00:00+00:00", "payload_schema_version": 1,
        "payload": payload,
    }


def test_the_documented_limit_is_500_levels():
    assert getattr(packet_core, "MAX_PACKET_NESTING_DEPTH", None) == LIMIT


def test_json_too_deep_for_the_decoder_raises_value_error():
    raw = json.dumps(_envelope({"schema_version": 1}))
    raw = raw.replace('"schema_version": 1}', '"schema_version": 1, "n": ' + "[" * 100_000 + "]" * 100_000 + "}", 1)

    with pytest.raises(ValueError, match="nest"):
        load_packet_json(raw)


def test_json_deeper_than_the_limit_raises_value_error():
    # Envelope (1) + payload (2) + 499 more levels = 501 levels.
    raw = json.dumps(_envelope({"schema_version": 1, "n": _nested(LIMIT - 1)}))

    with pytest.raises(ValueError, match="nest"):
        load_packet_json(raw)


def test_packet_at_the_limit_round_trips():
    # Envelope (1) + payload (2) + 498 more levels = 500 levels.
    packet = build_packet("x_probe", {"schema_version": 1, "n": _nested(LIMIT - 2)})

    restored = load_packet_json(export_packet_json(packet))

    assert restored["payload"]["n"] == _nested(LIMIT - 2)


@pytest.mark.parametrize("levels", [100, 250, LIMIT - 2])
def test_a_deep_packet_exported_by_0_1_0_still_loads(levels):
    # 0.1.0 had no limit and exported packets nested a few hundred levels;
    # 0.2.0 at first refused anything past 100.
    raw = json.dumps(_envelope({"schema_version": 1, "n": _nested(levels)}))

    assert load_packet_json(raw)["payload"]["n"] == _nested(levels)


@pytest.mark.parametrize("kind", ["dict", "list"])
def test_a_packet_at_the_limit_fits_below_the_recursion_limit(kind):
    # Redaction and JSON encoding recurse once per level. Python 3.10 and 3.11
    # add a frame for each comprehension, so a list level must not use one.
    payload = {"schema_version": 1, "n": _nested(LIMIT - 2, kind)}

    def round_trip():
        return load_packet_json(export_packet_json(build_packet("x_probe", payload)))

    restored = _with_stack_in_use(HOST_STACK_FRAMES, round_trip)

    assert restored["payload"]["n"] == _nested(LIMIT - 2, kind)


@pytest.mark.parametrize("levels", [LIMIT - 1, 5_000])
def test_export_refuses_a_packet_deeper_than_the_limit(levels):
    with pytest.raises(ValueError, match="nest"):
        export_packet_json(_envelope({"schema_version": 1, "n": _nested(levels)}))


@pytest.mark.parametrize("levels", [LIMIT - 1, 5_000])
def test_build_refuses_a_payload_deeper_than_the_limit(levels):
    with pytest.raises(ValueError, match="nest"):
        build_packet("x_probe", {"schema_version": 1, "n": _nested(levels)})


def test_build_refuses_deep_metadata():
    with pytest.raises(ValueError, match="nest"):
        build_packet("x_probe", {"schema_version": 1}, meta={"n": _nested(LIMIT - 1)})


def test_build_and_export_refuse_a_cyclic_payload():
    payload = {"schema_version": 1, "items": []}
    payload["items"].append(payload)

    with pytest.raises(ValueError, match="nest"):
        build_packet("x_probe", payload)
    with pytest.raises(ValueError, match="nest"):
        export_packet_json(_envelope(payload))


@pytest.mark.parametrize("kind", ["dict", "list"])
def test_a_packet_at_the_limit_renders_through_the_ui_json_redaction(kind):
    # redact_ui_json_payload redacts and then replaces non-finite numbers; the
    # second pass recursed through comprehensions, two frames per level before
    # Python 3.12.
    import json

    from role_aware_dashboard_toolkit.ui_json import redact_ui_json_payload

    packet = build_packet("x_probe", {"schema_version": 1, "n": _nested(LIMIT - 2, kind)})
    envelope = json.loads(export_packet_json(packet))

    rendered = _with_stack_in_use(HOST_STACK_FRAMES, lambda: redact_ui_json_payload(envelope))

    assert rendered["payload"]["n"] == envelope["payload"]["n"]


def test_non_finite_numbers_are_replaced_in_tuples_nested_to_the_limit():
    # A tuple was rebuilt from a generator, a frame per level on every version.
    from role_aware_dashboard_toolkit._json_safety import sanitize_non_finite_numbers

    deep = 1.0
    for _ in range(LIMIT):
        deep = (deep, float("nan"))

    sanitized = _with_stack_in_use(HOST_STACK_FRAMES, lambda: sanitize_non_finite_numbers(deep))

    for _ in range(LIMIT):
        assert sanitized[1] is None
        sanitized = sanitized[0]
    assert sanitized == 1.0


@pytest.mark.parametrize("levels", [10, LIMIT - 2])
def test_a_legal_packet_that_runs_out_of_stack_is_not_called_too_deep(monkeypatch, levels):
    # Before Python 3.12 the JSON decoder counts the caller's own frames, so a
    # host with a deep stack can hit RecursionError on a packet well within
    # the limit; saying "nesting exceeds 500 levels" sent it looking at the data.
    import role_aware_dashboard_toolkit.packets as packets

    raw = json.dumps(_envelope({"schema_version": 1, "n": _nested(levels)}))

    def decoder_out_of_stack(_raw):
        raise RecursionError("maximum recursion depth exceeded while decoding a JSON object")

    monkeypatch.setattr(packets, "strict_json_loads", decoder_out_of_stack)
    with pytest.raises(ValueError) as caught:
        load_packet_json(raw)

    message = str(caught.value)
    assert "exceeds" not in message
    assert "recursion limit" in message and f"{levels + 2} levels" in message


def test_a_packet_too_deep_for_the_decoder_still_names_the_limit(monkeypatch):
    import role_aware_dashboard_toolkit.packets as packets

    raw = json.dumps(_envelope({"schema_version": 1})).replace(
        '"schema_version": 1}', '"schema_version": 1, "n": ' + "[" * 600 + "]" * 600 + "}", 1)

    def decoder_out_of_stack(_raw):
        raise RecursionError("maximum recursion depth exceeded while decoding a JSON array")

    monkeypatch.setattr(packets, "strict_json_loads", decoder_out_of_stack)
    with pytest.raises(ValueError, match=f"nesting exceeds {LIMIT} levels"):
        load_packet_json(raw)
