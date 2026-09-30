"""Outcome comparisons retain observations, units, timestamps and visibility."""
from copy import deepcopy
import json

import pytest

from role_aware_dashboard_toolkit import append_checkpoint, build_run, compare_checkpoints, compare_runs
from role_aware_dashboard_toolkit.observability import coerce_telemetry_sample
from role_aware_dashboard_toolkit.runbook_panels import render_runbook_panel
from role_aware_dashboard_toolkit.security import make_security_context
from tests.test_runbook_contract import _FakeStreamlit, _runbook_config


def _checkpoint(metrics, *, units=None, ts="2026-09-20T10:00:00Z"):
    return {
        "checkpoint_id": "checkpoint", "controls": {"workers": 2},
        "telemetry_slice": {"metrics": metrics, "units": units or {}, "ts": ts},
    }


def _outcomes(left, right):
    return compare_checkpoints(left, right, include_telemetry=True)["telemetry_comparison"]


def test_opt_in_preserves_existing_comparison_shapes():
    checkpoint = _checkpoint({"latency": 120})
    assert set(compare_checkpoints(checkpoint, checkpoint)) == {
        "left_checkpoint_id", "right_checkpoint_id", "approval_transition", "control_diff",
    }
    run = build_run({"workers": 2})
    assert set(compare_runs(run, run)) == {"left_run", "right_run", "field_diff", "control_diff"}


def test_unchanged_controls_still_compare_changed_outcomes_and_show_sample_times():
    left = _checkpoint({"latency": 120, "quality": 0.8}, units={"latency": "ms"})
    right = _checkpoint({"latency": 90, "quality": 0.8}, units={"latency": "ms"}, ts="old-sample")
    before = deepcopy((left, right))
    comparison = compare_checkpoints(left, right, include_telemetry=True)
    assert comparison["control_diff"] == {}
    outcomes = comparison["telemetry_comparison"]
    assert outcomes["left_sample_ts"] == "2026-09-20T10:00:00Z"
    assert outcomes["right_sample_ts"] == "old-sample"
    assert outcomes["metrics"]["latency"] == {
        "from": 120.0, "to": 90.0, "from_unit": "ms", "to_unit": "ms",
        "delta": -30.0, "status": "comparable",
    }
    assert outcomes["metrics"]["quality"]["delta"] == 0
    assert (left, right) == before


@pytest.mark.parametrize("invalid", [None, True, False, "12", float("nan"), float("inf"),
                                      float("-inf"), 10**400, [], {}])
def test_invalid_values_never_become_numeric_deltas(invalid):
    row = _outcomes(_checkpoint({"cost": invalid}), _checkpoint({"cost": 12}))["metrics"]["cost"]
    assert row["from"] is None
    assert row["to"] == 12
    assert row["delta"] is None
    assert row["status"] == "invalid_value"
    json.dumps(row, allow_nan=False)


@pytest.mark.parametrize("left_unit,right_unit", [("ms", "s"), ("ms", ""), ("", "ms")])
def test_incompatible_or_partly_missing_units_do_not_imply_conversion(left_unit, right_unit):
    row = _outcomes(
        _checkpoint({"latency": 120}, units={"latency": left_unit}),
        _checkpoint({"latency": 0.1}, units={"latency": right_unit}),
    )["metrics"]["latency"]
    assert row["delta"] is None
    assert row["status"] == "unit_mismatch"
    assert (row["from_unit"], row["to_unit"]) == (left_unit, right_unit)


def test_metric_absence_and_unknown_timestamps_are_explicit():
    outcomes = _outcomes(_checkpoint({"removed": 2}, ts=None), _checkpoint({"added": 3}, ts=""))
    assert outcomes["left_sample_ts"] == outcomes["right_sample_ts"] == ""
    assert outcomes["metrics"]["removed"]["status"] == "missing_right"
    assert outcomes["metrics"]["added"]["status"] == "missing_left"
    assert all(row["delta"] is None for row in outcomes["metrics"].values())
    assert _outcomes({}, {}) == {"left_sample_ts": "", "right_sample_ts": "", "metrics": {}}


def test_overflowed_subtraction_is_not_a_finite_change():
    row = _outcomes(_checkpoint({"score": -1e308}), _checkpoint({"score": 1e308}))["metrics"]["score"]
    assert row["status"] == "non_finite_delta"
    assert row["delta"] is None
    json.dumps(row, allow_nan=False)


def test_normalized_dotted_names_do_not_overwrite_independent_metrics():
    outcomes = _outcomes(_checkpoint({"queue.depth": 20, "depth": 2}),
                         _checkpoint({"queue.depth": 10, "depth": 5}))
    assert outcomes["metrics"]["queue.depth"]["delta"] == -10
    assert outcomes["metrics"]["depth"]["delta"] == 3


def test_legacy_nested_samples_preserve_dotted_paths_and_maximum_list_value():
    left = {"telemetry_slice": {"queue": {"depth": [1, 3]}, "latency": 12}}
    right = {"telemetry_slice": {"queue": {"depth": [4, 2]}, "latency": 8}}
    rows = _outcomes(left, right)["metrics"]
    assert set(rows) == {"queue.depth", "latency"}
    assert rows["queue.depth"]["delta"] == 1
    assert rows["latency"]["delta"] == -4


def test_units_survive_normalized_capture_and_are_detached():
    payload = {"metrics": {"latency": 120}, "units": {"latency": " ms ", "absent": "s"}, "ts": "sample"}
    sample = coerce_telemetry_sample(payload)
    run = append_checkpoint(build_run({}), {}, telemetry=sample)
    payload["units"]["latency"] = "s"
    sample["units"]["latency"] = "minutes"
    captured = run["checkpoints"][0]["telemetry_slice"]
    assert captured["units"] == {"latency": "ms"}
    assert captured["ts"] == "sample"
    assert "units" not in coerce_telemetry_sample({"metrics": {"latency": 10}})


def test_run_comparison_uses_final_checkpoint_without_backfilling_older_samples():
    left = append_checkpoint(build_run({}), {}, telemetry={"ts": "earlier", "metrics": {"latency": 120}})
    right = append_checkpoint(build_run({}), {}, telemetry={"ts": "latest", "metrics": {"latency": 90}})
    right = append_checkpoint(right, {})
    outcomes = compare_runs(left, right, include_telemetry=True)["telemetry_comparison"]
    assert outcomes["left_checkpoint_id"] == left["last_checkpoint_id"]
    assert outcomes["right_checkpoint_id"] == right["last_checkpoint_id"]
    assert outcomes["right_sample_ts"] == ""
    assert outcomes["metrics"]["latency"]["status"] == "missing_right"
    empty = compare_runs(build_run({}), build_run({}), include_telemetry=True)["telemetry_comparison"]
    assert empty["left_checkpoint_id"] == empty["right_checkpoint_id"] == ""
    assert empty["metrics"] == {}


@pytest.mark.parametrize("can_view_metrics", [False, True])
def test_runbook_comparison_visibility_matches_checkpoint_telemetry(can_view_metrics):
    from role_aware_dashboard_toolkit import InMemoryRunStore

    store = InMemoryRunStore()
    for run_id in ("one", "two"):
        run = build_run({}, run_id=run_id)
        for value in (20, 15):
            run = append_checkpoint(run, {}, telemetry={
                "ts": "private-sample-time", "metrics": {"private-latency": value},
                "units": {"private-latency": "private-unit"},
            })
        store.save(run)
    st = _FakeStreamlit()
    ctx = make_security_context("Team", {"can_view_team_ops": True, "can_view_metrics": can_view_metrics})
    render_runbook_panel(st, _runbook_config(store), ctx)
    rendered = repr(st.events)
    assert ("Observed Outcomes" in rendered) is can_view_metrics
    assert ("private-latency" in rendered) is can_view_metrics
    assert ("private-sample-time" in rendered) is can_view_metrics
    assert ("private-unit" in rendered) is can_view_metrics


def _comparison_app():
    import streamlit as st
    from role_aware_dashboard_toolkit import DashboardConfig, InMemoryRunStore, append_checkpoint, build_run
    from role_aware_dashboard_toolkit.runbook_panels import render_runbook_panel
    from role_aware_dashboard_toolkit.security import make_security_context

    if "store" not in st.session_state:
        store = InMemoryRunStore()
        run = build_run({"workers": 2}, run_id="comparison-run")
        for index, value in enumerate((120, 90)):
            run = append_checkpoint(run, {"workers": 2 + index}, telemetry={
                "ts": f"sample-{index}", "metrics": {"latency": value}, "units": {"latency": "ms"},
            })
        store.save(run)
        st.session_state["store"] = store
    access = st.selectbox("Metric access", ["Visible", "Hidden"], key="access")
    ctx = make_security_context("Team", {"can_view_team_ops": True, "can_view_metrics": access == "Visible"})
    render_runbook_panel(st, DashboardConfig(run_store=st.session_state["store"]), ctx)


def test_real_comparison_controls_update_outcomes_and_role_hides_them():
    AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
    app = AppTest.from_function(_comparison_app).run()
    assert not app.exception
    assert app.dataframe[-1].value.iloc[0]["Change"] == -30
    assert app.dataframe[-1].value.iloc[0]["Left unit"] == "ms"
    assert any("Left sample: sample-0 | Right sample: sample-1" in caption.value for caption in app.caption)
    left_id = app.selectbox(key="_radt_compare_checkpoint_left").value
    app.selectbox(key="_radt_compare_checkpoint_right").select(left_id).run()
    assert not app.exception
    assert app.dataframe[-1].value.iloc[0]["Change"] == 0
    app.selectbox(key="access").select("Hidden").run()
    assert not app.exception
    assert not any(header.value == "Observed Outcomes" for header in app.subheader)
    assert not any("latency" in item.value for item in app.json)
