"""Telemetry deltas drop binary floating-point noise from the subtraction."""
from __future__ import annotations

import pytest

import role_aware_dashboard_toolkit as radt
from examples.operator_review.report import render_run_report
from role_aware_dashboard_toolkit import compare_checkpoints
from role_aware_dashboard_toolkit.observability import coerce_telemetry_sample, summarize_observability


def _delta(old, new):
    left = {"checkpoint_id": "left", "controls": {}, "telemetry_slice": {"metrics": {"m": old}}}
    right = {"checkpoint_id": "right", "controls": {}, "telemetry_slice": {"metrics": {"m": new}}}
    return compare_checkpoints(left, right, include_telemetry=True)["telemetry_comparison"]["metrics"]["m"]["delta"]


@pytest.mark.parametrize(
    ("old", "new", "expected"),
    [
        (0.1, 0.35, 0.25),            # raw subtraction: 0.24999999999999997
        (0.3, 0.1, -0.2),             # raw: -0.19999999999999998
        (0.1, 0.3, 0.2),              # raw: 0.19999999999999998
        (1e9, 1000000000.1, 0.1),     # raw: 0.10000002384185791
        (100, 70, -30.0),
        (1e-12, 3e-12, 2e-12),
        (0.1234567890123, 0.1234567890124, 1e-13),
        (2.5, 2.5, 0.0),
    ],
)
def test_delta_keeps_only_the_precision_of_its_endpoints(old, new, expected):
    delta = _delta(old, new)

    assert delta == expected
    assert repr(delta) == repr(expected)


def test_zero_delta_is_never_negative_zero():
    assert repr(_delta(-0.1, -0.1)) == "0.0"


def test_readable_report_shows_rounded_deltas():
    run = radt.build_run({"model": "small"}, run_id="precision-demo")
    for label, score in [("Baseline", 0.1), ("Candidate", 0.35)]:
        run = radt.append_checkpoint(
            run, {"model": "small"}, label=label,
            telemetry={"ts": "2026-09-20T10:00:00+00:00", "metrics": {"score": score}},
        )

    html = render_run_report(radt.build_run_packet(radt.end_run(run, outcome="accepted")))

    assert "<td>0.25</td>" in html
    assert "0.24999999999999997" not in html


@pytest.mark.parametrize(
    ("old", "new", "expected"),
    [(0.1, 0.35, 0.25), (0.3, 0.1, -0.2), (100, 130, 30.0), (1e9, 1000000000.1, 0.1)],
)
def test_observability_drift_delta_matches_the_comparison_delta(old, new, expected):
    history = [
        coerce_telemetry_sample({"metrics": {"risk_score": old}}),
        coerce_telemetry_sample({"metrics": {"risk_score": new}}),
    ]
    drift = summarize_observability(history)["drift"]["risk_score"]

    assert drift["delta"] == expected == _delta(old, new)
    assert (drift["from"], drift["to"]) == (float(old), float(new))
