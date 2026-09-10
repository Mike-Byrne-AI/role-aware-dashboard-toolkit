import json
from pathlib import Path

import role_aware_dashboard_toolkit.observability as observability
from role_aware_dashboard_toolkit import AuditLog
from role_aware_dashboard_toolkit.observability import (
    TELEMETRY_SCHEMA_VERSION,
    build_observability_snapshot,
    coerce_telemetry_sample,
    summarize_recent_changes,
)
from role_aware_dashboard_toolkit.runtime import (
    build_runtime_diagnostic_record,
    normalize_telemetry,
    summarize_telemetry,
)
from role_aware_dashboard_toolkit.store_diagnostics import build_read_error as build_store_read_error


def test_coerce_telemetry_sample_adds_contract_fields():
    sample = coerce_telemetry_sample({"metrics": {"latency_ms": 10}, "source": "gateway", "health": {"status": "ok"}})
    assert sample["schema_version"] == TELEMETRY_SCHEMA_VERSION
    assert sample["source"] == "gateway"
    assert sample["health"]["status"] == "ok"


def test_non_finite_telemetry_is_removed_or_sanitized_before_output():
    metrics = normalize_telemetry(
        {
            "latency_ms": 10,
            "nan": float("nan"),
            "positive_infinity": float("inf"),
            "nested": {
                "negative_infinity": float("-inf"),
                "queue_depth": 3,
            },
        }
    )

    assert metrics == {
        "latency_ms": 10.0,
        "nested.queue_depth": 3.0,
        "queue_depth": 3.0,
    }
    assert summarize_telemetry(metrics)["max_value"] == 10.0

    sample = coerce_telemetry_sample(
        {
            "metrics": {"latency_ms": 10, "bad": float("nan")},
            "labels": {"weight": float("inf")},
            "health": {"score": float("-inf"), "status": "ok"},
        }
    )

    assert sample["metrics"] == {"latency_ms": 10.0}
    assert sample["labels"]["weight"] is None
    assert sample["health"] == {"score": None, "status": "ok"}
    json.dumps(sample, allow_nan=False)


def test_oversized_integer_metrics_are_ignored_without_losing_healthy_values():
    metrics = {
        "healthy": 1,
        "oversized_positive": 10**400,
        "nested": {
            "oversized_negative": -(10**400),
            "queue_depth": 3,
        },
    }
    expected = {"healthy": 1.0, "nested.queue_depth": 3.0, "queue_depth": 3.0}

    assert normalize_telemetry(metrics) == expected
    sample = coerce_telemetry_sample({"metrics": metrics})
    assert sample["metrics"] == expected
    snapshot = build_observability_snapshot([{"metrics": metrics}])
    assert snapshot["latest"] == expected
    json.dumps(snapshot, allow_nan=False)


def test_observability_snapshot_sanitizes_untrusted_history_and_audit_values():
    history = [
        {
            "ts": "2026-07-29T00:00:00+00:00",
            "metrics": {"finite": 1, "bad": float("nan")},
            "health": {"score": float("inf")},
        }
    ]
    audit = AuditLog()
    audit.log_control_change("limit", 1, float("-inf"), role="Admin")

    snapshot = build_observability_snapshot(history, audit)

    assert snapshot["latest"] == {"finite": 1.0}
    assert snapshot["health"] == {"score": None}
    assert snapshot["recent_changes"][0]["new"] is None
    json.dumps(snapshot, allow_nan=False)


def test_build_observability_snapshot_merges_recent_change_summary():
    history = [coerce_telemetry_sample({"metrics": {"latency_ms": 10}})]
    audit = AuditLog()
    audit.log_control_change("temperature", 0.7, 0.8, role="Admin")
    snapshot = build_observability_snapshot(history, audit)
    assert snapshot["sample_count"] == 1
    assert snapshot["recent_control_changes"] == 1
    assert snapshot["recent_changes"][0]["control"] == "temperature"


def test_summarize_recent_changes_limit():
    audit = AuditLog()
    history = [coerce_telemetry_sample({"metrics": {"risk_score": 0.1}})]
    for idx in range(6):
        audit.log_control_change(f"k{idx}", idx, idx + 1, role="Admin")
    changes = summarize_recent_changes(history, audit, limit=3)
    assert len(changes) == 3
    assert changes[0]["control"] == "k5"


def test_history_dataframe_helpers_return_none_when_pandas_unavailable(monkeypatch):
    monkeypatch.setattr(observability, "pd", None)
    monkeypatch.setattr(observability, "PANDAS_AVAILABLE", False)
    monkeypatch.setattr(observability, "_PANDAS_CHECKED", True)

    history = [coerce_telemetry_sample({"metrics": {"latency_ms": 10}})]

    assert observability.history_as_dataframe_available() is False
    assert observability.history_as_dataframe(history) is None


def test_runtime_diagnostic_record_includes_fallback():
    record = build_runtime_diagnostic_record("ui", "st.graphviz_chart", RuntimeError("no graphviz"), fallback="DOT markdown")
    assert record["stage"] == "ui"
    assert record["source"] == "st.graphviz_chart"
    assert record["exception_type"] == "RuntimeError"
    assert record["error_type"] == "RuntimeError"
    assert record["message"] == "A callback failed."
    assert record["diagnostic"]["code"] == "RADT-CALLBACK"
    assert record["fallback"] == "DOT markdown"


def test_runtime_diagnostic_record_redacts_local_paths(tmp_path):
    secret_path = tmp_path / "ui" / "graphviz.dot"
    fallback_path = tmp_path / "fallback" / "raw.dot"
    record = build_runtime_diagnostic_record(
        f"ui at {secret_path}",
        f"st.graphviz_chart {secret_path}",
        RuntimeError(f"cannot render {secret_path}"),
        fallback=f"DOT markdown from {fallback_path}",
    )

    assert record["stage"] == "ui at <redacted-local-path>"
    assert record["source"] == "st.graphviz_chart <redacted-local-path>"
    assert record["message"] == "A callback failed."
    assert record["diagnostic"]["code"] == "RADT-CALLBACK"
    assert record["fallback"] == "DOT markdown from <redacted-local-path>"
    assert str(fallback_path) not in record["fallback"]
    assert str(secret_path) not in record["stage"]
    assert str(secret_path) not in record["source"]
    assert str(secret_path) not in record["message"]


def test_runtime_diagnostic_record_redacts_standard_windows_oserror_filename():
    secret_path = r"C:\Private Root\Dash Forge\secret file.json"

    record = build_runtime_diagnostic_record(
        "ui",
        "st.graphviz_chart",
        PermissionError(13, "render denied", secret_path),
    )

    assert record["message"] == "A callback failed."
    assert record["diagnostic"]["code"] == "RADT-CALLBACK"


def test_store_read_error_contract_includes_type_aliases():
    path = Path("tmp/read_error.json")
    store_error = build_store_read_error(path, ValueError("bad data"))

    assert store_error["error_type"] == "ValueError"
    assert store_error["exception_type"] == store_error["error_type"]
