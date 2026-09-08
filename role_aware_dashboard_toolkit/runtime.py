# role_aware_dashboard_toolkit/runtime.py
# Generic runtime helpers salvaged from larger control-panel patterns.
#
# These helpers are intentionally domain-neutral. They provide:
#   - safe function execution wrappers
#   - telemetry normalization for messy runtime payloads
#   - best-effort runtime cleanup for heavier apps

from __future__ import annotations

import gc
import math
import warnings
from dataclasses import dataclass
from typing import Any
from collections.abc import Callable, Iterable

from .audit import AuditLog
from .path_redaction import redact_text_local_paths


@dataclass(frozen=True)
class RuntimeErrorRecord:
    stage: str
    source: str
    exception_type: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "stage": self.stage,
            "source": self.source,
            "exception_type": self.exception_type,
            "error_type": self.exception_type,
            "message": self.message,
        }


def build_runtime_error_record(stage: str, source: str, exc: Exception) -> RuntimeErrorRecord:
    return RuntimeErrorRecord(
        stage=redact_text_local_paths(str(stage)),
        source=redact_text_local_paths(str(source)),
        exception_type=type(exc).__name__,
        message=redact_text_local_paths(str(exc)),
    )


def build_runtime_diagnostic_record(stage: str, source: str, exc: Exception, *, fallback: str = "") -> dict[str, str]:
    record = build_runtime_error_record(stage, source, exc).to_dict()
    record["fallback"] = redact_text_local_paths(str(fallback or ""))
    return record


def safe_call(
    func: Callable[..., Any],
    *args: Any,
    default: Any = None,
    on_error: Callable[[Exception], None] | None = None,
    **kwargs: Any,
) -> Any:
    """Call a function and return ``default`` on failure.

    Failures are reported to ``on_error`` when supplied. If no error sink is
    supplied, a ``RuntimeWarning`` is emitted so the fallback path is visible.
    """
    try:
        return func(*args, **kwargs)
    except Exception as exc:
        record = build_runtime_error_record("safe_call", _callable_source(func), exc)
        _attach_runtime_error_record(exc, record)
        if on_error is not None:
            on_error(exc)
        else:
            _warn_safe_call_failure(record)
        return default


def normalize_telemetry(*payloads: Any) -> dict[str, float]:
    """Extract stable numeric telemetry from arbitrary nested payloads.

    Rules:
    - nested dict/list structures are traversed recursively
    - only numeric leaf values are kept
    - non-finite values are ignored
    - repeated keys keep the maximum observed value
    - boolean values are ignored to avoid accidental metric pollution
    """
    normalized: dict[str, float] = {}
    for payload in payloads:
        _walk_payload(payload, normalized)
    return normalized


def summarize_telemetry(*payloads: Any) -> dict[str, Any]:
    """Return a small stable summary for normalized numeric telemetry."""
    normalized = normalize_telemetry(*payloads)
    if not normalized:
        return {
            "metrics": {},
            "max_metric": None,
            "max_value": 0.0,
            "metric_count": 0,
        }
    max_metric, max_value = max(normalized.items(), key=lambda item: item[1])
    return {
        "metrics": normalized,
        "max_metric": max_metric,
        "max_value": float(max_value),
        "metric_count": len(normalized),
    }


def cleanup_runtime(
    *,
    audit: AuditLog | None = None,
    refs: Iterable[tuple[Any, str]] | None = None,
    run_gc: bool = True,
    try_torch_cuda_empty_cache: bool = True,
) -> dict[str, Any]:
    """Best-effort cleanup for heavier Streamlit or API runtimes.

    - stops the audit writer if present
    - clears selected object attributes by setting them to ``None``
    - optionally triggers ``gc.collect()``
    - optionally calls ``torch.cuda.empty_cache()`` if torch is installed
    """
    report: dict[str, Any] = {
        "audit_writer_stopped": False,
        "cleared_refs": [],
        "gc_collected": None,
        "cuda_cache_cleared": False,
        "warnings": [],
        "error_records": [],
    }

    if audit is not None:
        try:
            audit.stop_writer()
            report["audit_writer_stopped"] = True
        except Exception as exc:
            _record_runtime_warning(report, "audit.stop_writer", "AuditLog.stop_writer", exc, "audit.stop_writer failed")

    for item in refs or []:
        source = "refs"
        try:
            obj, attr = item
            source = f"{type(obj).__name__}.{attr}"
            setattr(obj, attr, None)
            report["cleared_refs"].append(attr)
        except Exception as exc:
            _record_runtime_warning(report, "clear_ref", source, exc, "clear ref failed")

    if run_gc:
        try:
            report["gc_collected"] = gc.collect()
        except Exception as exc:
            _record_runtime_warning(report, "gc.collect", "gc.collect", exc, "gc.collect failed")

    if try_torch_cuda_empty_cache:
        _cleanup_torch_cuda(report)

    return report


def _cleanup_torch_cuda(report: dict[str, Any]) -> None:
    try:
        import torch  # type: ignore
    except ModuleNotFoundError as exc:
        if exc.name == "torch":
            return
        _record_runtime_warning(report, "cuda_cleanup", "import torch", exc, "cuda cleanup skipped")
        return
    except Exception as exc:
        _record_runtime_warning(report, "cuda_cleanup", "import torch", exc, "cuda cleanup skipped")
        return

    source = "torch.cuda"
    try:
        cuda = getattr(torch, "cuda", None)
        if not bool(cuda):
            return
        source = "torch.cuda.is_available"
        if not cuda.is_available():
            return
        source = "torch.cuda.empty_cache"
        cuda.empty_cache()
        report["cuda_cache_cleared"] = True
    except Exception as exc:
        _record_runtime_warning(
            report,
            "cuda_cleanup",
            source,
            exc,
            "cuda cleanup skipped",
        )


def _callable_source(func: Callable[..., Any]) -> str:
    return str(getattr(func, "__qualname__", getattr(func, "__name__", type(func).__name__)))


def _attach_runtime_error_record(exc: Exception, record: RuntimeErrorRecord) -> None:
    try:
        exc.role_aware_dashboard_toolkit_error_record = record
    except Exception as attach_exc:
        warnings.warn(
            (
                "safe_call could not attach role_aware_dashboard_toolkit_error_record to "
                f"{type(exc).__name__}: {type(attach_exc).__name__}: {attach_exc}"
            ),
            RuntimeWarning,
            stacklevel=3,
        )


def _warn_safe_call_failure(record: RuntimeErrorRecord) -> None:
    warnings.warn(
        (
            f"safe_call suppressed {record.exception_type} from {record.source}; "
            f"returning default: {record.message}"
        ),
        RuntimeWarning,
        stacklevel=3,
    )


def _record_runtime_warning(
    report: dict[str, Any],
    stage: str,
    source: str,
    exc: Exception,
    warning_prefix: str,
) -> None:
    record = build_runtime_error_record(stage, source, exc)
    report["error_records"].append(record.to_dict())
    report["warnings"].append(f"{warning_prefix}: {record.exception_type}: {record.message}")


def _walk_payload(payload: Any, out: dict[str, float], prefix: str = "") -> None:
    if isinstance(payload, dict):
        for key, value in payload.items():
            key_str = str(key)
            next_prefix = key_str if not prefix else f"{prefix}.{key_str}"
            _walk_payload(value, out, next_prefix)
        return
    if isinstance(payload, (list, tuple)):
        for item in payload:
            _walk_payload(item, out, prefix)
        return
    if isinstance(payload, bool):
        return
    if isinstance(payload, (int, float)):
        metric_key = prefix or "value"
        try:
            numeric = float(payload)
        except OverflowError:
            return
        if not math.isfinite(numeric):
            return
        out[metric_key] = max(numeric, out.get(metric_key, float('-inf')))
        if "." in metric_key:
            leaf_key = metric_key.rsplit(".", 1)[-1]
            out[leaf_key] = max(numeric, out.get(leaf_key, float('-inf')))
