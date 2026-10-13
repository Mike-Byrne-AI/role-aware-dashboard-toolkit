from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from collections.abc import Callable

from ._json_safety import sanitize_non_finite_numbers
from ._optional_pandas import load_optional_pandas
from ._record_projection import project_record
from .audit import AuditLog
from .compare import _metric_delta
from .diagnostics import diagnostic_text
from .runtime import normalize_telemetry, summarize_telemetry

pd = None
PANDAS_AVAILABLE = False
_PANDAS_CHECKED = False


TelemetryHook = Callable[[], Any]
TELEMETRY_SCHEMA_VERSION = 1


@dataclass
class ObservabilityConfig:
    enabled: bool = False
    telemetry_hook: TelemetryHook | None = None
    history_limit: int = 50
    show_summary: bool = True
    title: str = "Observability"
    service_name: str = ""


class ObservabilityPanel:
    """Optional observability surface for Role-Aware Dashboard Toolkit dashboards.

    ``can_read_audit`` checks live authority after sampling, immediately before
    audit reads. Omitting it preserves standalone callers' trusted audit access.
    """

    def __init__(
        self,
        config: ObservabilityConfig,
        audit: AuditLog,
        session_state: dict[str, Any],
        *,
        can_read_audit: Callable[[], bool] | None = None,
        registry: Any = None,
    ) -> None:
        self.config = config
        self.audit = audit
        self.session_state = session_state
        self._can_read_audit = can_read_audit
        self._registry = registry

    @property
    def _history_key(self) -> str:
        return "_radt_observability_history"

    def sample(self) -> dict[str, Any] | None:
        hook = self.config.telemetry_hook
        if hook is None:
            return None
        payload = hook()
        if payload is None:
            return None
        return coerce_telemetry_sample(payload)

    def record_sample(self) -> dict[str, Any] | None:
        sample = self.sample()
        if sample is None:
            return None
        history = list(self.session_state.get(self._history_key, []))
        history.append(sample)
        limit = max(1, int(self.config.history_limit))
        if len(history) > limit:
            history = history[-limit:]
        self.session_state[self._history_key] = history
        return sample

    def history(self) -> list[dict[str, Any]]:
        history = self.session_state.get(self._history_key, [])
        if not isinstance(history, list):
            return []
        sanitized = sanitize_non_finite_numbers(list(history))
        return sanitized if isinstance(sanitized, list) else []

    def render(self, st: Any) -> None:
        st.divider()
        with st.expander(self.config.title, expanded=False):
            try:
                latest = self.record_sample()
            except Exception as exc:
                latest = None
                st.warning(
                    f"Telemetry sampling failed ({type(exc).__name__}). "
                    + diagnostic_text("RADT-TELEMETRY")
                )
            source_history = self.history()
            history = project_record(source_history, self._registry)

            if latest is None and not history:
                st.caption("No telemetry samples yet.")
                return

            if latest is None:
                st.caption(
                    f"Showing the retained sample from {history[-1].get('ts', '')}; "
                    "no new sample was collected on this render."
                )

            # Sampling may invoke host code and outlive a role grant. Recheck
            # here so metrics never grant access to audit values or counts.
            audit = self.audit
            if self._can_read_audit is not None and not self._can_read_audit():
                audit = None
            snapshot = project_record(build_observability_snapshot(history, audit), self._registry)

            latest_metrics = snapshot.get("latest", {})
            if latest_metrics:
                st.subheader("Latest Metrics")
                if hasattr(st, "metric"):
                    metric_cols = st.columns(min(4, max(1, len(latest_metrics))))
                    for idx, (name, value) in enumerate(list(latest_metrics.items())[:4]):
                        with metric_cols[idx]:
                            st.metric(name, value)
                else:
                    st.json(latest_metrics)
            elif latest is not None:
                st.json(project_record({"ts": latest["ts"], "metrics": latest["metrics"]}, self._registry))
            else:
                st.caption("Telemetry hook returned no new sample on this render.")

            if self.config.show_summary:
                st.subheader("Summary")
                st.json(snapshot)

            if history_as_dataframe_available() and history:
                st.subheader("History")
                radt = history_as_dataframe(project_record(history, self._registry))
                if radt is not None:
                    st.dataframe(radt, width="stretch", hide_index=True)
            elif history:
                st.subheader("History")
                st.json(project_record(history[-10:], self._registry))

            # Keep the original normalized evidence for an authorized checkpoint.
            # Native displays project this same sample and timestamp independently.
            if source_history:
                self.session_state["_radt_last_telemetry"] = deepcopy(source_history[-1])


def coerce_telemetry_sample(payload: Any) -> dict[str, Any]:
    """Normalize a telemetry payload into a stable sample dict."""
    if isinstance(payload, dict) and isinstance(payload.get("metrics"), dict):
        metrics = normalize_telemetry(payload["metrics"])
        ts = _coerce_ts(payload.get("ts"))
        labels = sanitize_non_finite_numbers(dict(payload.get("labels") or {}))
        source = str(payload.get("source") or "app")
        service = str(payload.get("service") or "")
        health = sanitize_non_finite_numbers(dict(payload.get("health") or {}))
    else:
        metrics = normalize_telemetry(payload)
        ts = _coerce_ts(None)
        labels = {}
        source = "app"
        service = ""
        health = {}
    sample = {
        "schema_version": TELEMETRY_SCHEMA_VERSION,
        "ts": ts,
        "metrics": metrics,
        "labels": labels,
        "source": source,
        "service": service,
        "health": health,
    }
    if isinstance(payload, dict) and isinstance(payload.get("units"), dict):
        sample["units"] = {
            str(name): unit.strip()
            for name, unit in payload["units"].items()
            if isinstance(unit, str) and unit.strip() and str(name) in metrics
        }
    return sample


def history_as_dataframe(history: list[dict[str, Any]]):
    pandas = _load_pandas()
    if pandas is None:
        return None
    rows: list[dict[str, Any]] = []
    for sample in history:
        row = {"ts": sample.get("ts", "")}
        row.update(normalize_telemetry(sample.get("metrics", {})))
        if sample.get("source"):
            row["source"] = sample.get("source")
        rows.append(row)
    if not rows:
        return None
    return pandas.DataFrame(rows)


def history_as_dataframe_available() -> bool:
    return _load_pandas() is not None


def summarize_observability(history: list[dict[str, Any]], audit: AuditLog | None = None) -> dict[str, Any]:
    if not history:
        return {
            "sample_count": 0,
            "metric_count": 0,
            "latest": {},
            "drift": {},
            "recent_control_changes": 0,
            "health": {},
            "recent_changes": [],
        }

    latest = normalize_telemetry(history[-1].get("metrics", {}))
    drift: dict[str, dict[str, float]] = {}
    if len(history) >= 2:
        first = normalize_telemetry(history[0].get("metrics", {}))
        for key, new_val in latest.items():
            if key not in first:
                continue
            old_val = first[key]
            if not isinstance(old_val, (int, float)) or not isinstance(new_val, (int, float)):
                continue
            drift[key] = {
                "from": float(old_val),
                "to": float(new_val),
                # Same rule as checkpoint comparisons: no binary subtraction noise.
                "delta": _metric_delta(float(old_val), float(new_val)),
            }

    recent_control_changes = 0
    recent_changes: list[dict[str, Any]] = []
    if audit is not None:
        for evt in audit.recent(100):
            if evt.get("type") == "control_change":
                recent_control_changes += 1
        recent_changes = summarize_recent_changes(history, audit)

    summary = summarize_telemetry(latest)
    summary.update(
        {
            "sample_count": len(history),
            "latest": latest,
            "drift": drift,
            "recent_control_changes": recent_control_changes,
            "health": latest_health(history),
            "recent_changes": recent_changes,
        }
    )
    sanitized = sanitize_non_finite_numbers(summary)
    return sanitized if isinstance(sanitized, dict) else {}


def summarize_recent_changes(history: list[dict[str, Any]], audit: AuditLog | None, *, limit: int = 5) -> list[dict[str, Any]]:
    if audit is None:
        return []
    output: list[dict[str, Any]] = []
    latest = history[-1] if history else {}
    latest_metrics = (
        normalize_telemetry(latest.get("metrics", {}))
        if isinstance(latest, dict)
        else {}
    )
    for evt in reversed(audit.recent(100)):
        if evt.get("type") != "control_change":
            continue
        entry = {
            "ts": evt.get("ts", ""),
            "control": evt.get("key", ""),
            "new": evt.get("new"),
            "role": evt.get("role", ""),
            "latest_metrics": latest_metrics,
        }
        output.append(entry)
        if len(output) >= limit:
            break
    sanitized = sanitize_non_finite_numbers(output)
    return sanitized if isinstance(sanitized, list) else []


def latest_health(history: list[dict[str, Any]]) -> dict[str, Any]:
    if not history:
        return {}
    latest = history[-1]
    health = latest.get("health") or {}
    if health:
        sanitized = sanitize_non_finite_numbers(dict(health))
        return sanitized if isinstance(sanitized, dict) else {}
    metrics = normalize_telemetry(latest.get("metrics") or {})
    return {
        "metric_keys": sorted(metrics.keys()),
        "source": latest.get("source", ""),
    }


def build_observability_snapshot(history: list[dict[str, Any]], audit: AuditLog | None = None) -> dict[str, Any]:
    summary = summarize_observability(history, audit)
    summary["latest_ts"] = history[-1].get("ts", "") if history else ""
    sanitized = sanitize_non_finite_numbers(summary)
    return sanitized if isinstance(sanitized, dict) else {}


def _coerce_ts(value: Any) -> str:
    if isinstance(value, str) and value.strip():
        return value
    return datetime.now(timezone.utc).isoformat()


def _load_pandas():
    global pd, PANDAS_AVAILABLE, _PANDAS_CHECKED
    pd, PANDAS_AVAILABLE, _PANDAS_CHECKED = load_optional_pandas(
        pd,
        PANDAS_AVAILABLE,
        checked=_PANDAS_CHECKED,
    )
    return pd


__all__ = [
    "TELEMETRY_SCHEMA_VERSION",
    "ObservabilityConfig",
    "ObservabilityPanel",
    "build_observability_snapshot",
    "coerce_telemetry_sample",
    "history_as_dataframe",
    "latest_health",
    "summarize_observability",
    "summarize_recent_changes",
]
