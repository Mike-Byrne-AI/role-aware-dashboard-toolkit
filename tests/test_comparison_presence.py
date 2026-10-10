"""Comparisons retain removals and additions even when values are empty or null."""

from copy import deepcopy

import pytest

from role_aware_dashboard_toolkit import (
    append_checkpoint,
    build_compare_packet,
    build_run,
    compare_runs,
    export_packet_json,
    load_packet_json,
    profile_diff,
)
from role_aware_dashboard_toolkit.ledger import build_run_ledger, reconstruct_controls_from_ledger


@pytest.mark.parametrize("value", [8, None])
@pytest.mark.parametrize("include_telemetry", [False, True])
def test_run_comparison_preserves_empty_final_snapshot(value, include_telemetry):
    before = build_run({"choice": value}, run_id="before")
    after = append_checkpoint(build_run({"choice": value}, run_id="after"), {})
    originals = deepcopy((before, after))

    comparison = compare_runs(before, after, include_telemetry=include_telemetry)

    assert comparison["control_diff"] == {"choice": {"from": value, "to": None}}
    assert comparison["right_run"]["control_diff_count"] == 1
    assert compare_runs(after, before)["control_diff"] == {
        "choice": {"from": None, "to": value},
    }
    assert (before, after) == originals

    packet = build_compare_packet(
        diff_type="runs", source_ids=["before", "after"], diff=comparison,
    )
    assert load_packet_json(export_packet_json(packet))["payload"]["diff"] == comparison


@pytest.mark.parametrize("latest_is_null", [False, True])
def test_run_comparison_keeps_fallback_for_unavailable_latest_snapshot(latest_is_null):
    baseline = build_run({"workers": 8})
    legacy = build_run({"workers": 8})
    if latest_is_null:
        legacy["latest_controls"] = None
    else:
        del legacy["latest_controls"]

    assert compare_runs(baseline, legacy)["control_diff"] == {}
    assert compare_runs(legacy, baseline)["control_diff"] == {}


def test_two_empty_final_snapshots_do_not_resurrect_different_initial_controls():
    left = append_checkpoint(build_run({"workers": 8}), {})
    right = append_checkpoint(build_run({"workers": 3}), {})

    assert compare_runs(left, right)["control_diff"] == {}


@pytest.mark.parametrize(
    "before,after,expected",
    [
        ({}, {"choice": None}, {"choice": {"from": None, "to": None}}),
        ({"choice": None}, {}, {"choice": {"from": None, "to": None}}),
        ({"choice": None}, {"choice": None}, {}),
        ({}, {}, {}),
        ({"choice": 0}, {"choice": None}, {"choice": {"from": 0, "to": None}}),
        ({"choice": None}, {"choice": 0}, {"choice": {"from": None, "to": 0}}),
    ],
)
def test_profile_diff_tracks_key_presence_without_changing_value_shape(before, after, expected):
    originals = deepcopy((before, after))

    assert profile_diff(before, after) == expected
    assert (before, after) == originals


def test_ledger_records_null_key_removal_and_reconstructs_empty_snapshot():
    run = append_checkpoint(build_run({"choice": None}), {})

    ledger = build_run_ledger(run)

    checkpoint = next(entry for entry in ledger["entries"] if entry["entry_type"] == "checkpoint")
    assert checkpoint["controls_diff"] == {"choice": {"from": None, "to": None}}
    assert ledger["latest_controls"] == {}
    assert reconstruct_controls_from_ledger(ledger) == {}
