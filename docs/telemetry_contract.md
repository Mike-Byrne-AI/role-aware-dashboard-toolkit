# Telemetry and runtime diagnostics

Role-Aware Dashboard Toolkit telemetry is intentionally descriptive. It normalizes numeric
application measurements for dashboard visibility without assigning business
meaning or making automated decisions.

## Sample shape

`ObservabilityPanel` normalizes each sample to:

- `schema_version`
- `ts`
- `metrics`
- `labels`
- `source`
- `service`
- `health`

A telemetry hook may return that full shape or any nested numeric payload.
Nested metric names are retained with dotted paths, repeated keys keep the
maximum observed value, and booleans are ignored.

```python
import role_aware_dashboard_toolkit as radt

config = radt.ObservabilityConfig(
    enabled=True,
    telemetry_hook=lambda: {
        "metrics": {"latency_ms": 18.4, "queue": {"depth": 2}},
        "labels": {"region": "east"},
        "health": {"status": "ok"},
        "source": "service",
    },
    history_limit=30,
)
```

The core summary remains dictionary-based. Install `role-aware-dashboard-toolkit[pandas]` only for
dataframe-backed history views.

## Runtime failures

`safe_call()` returns the configured fallback when a callback raises, but it
does not hide the failure:

- with `on_error`, the original exception is delivered to the handler with a
  `role_aware_dashboard_toolkit_error_record` when attachment is possible
- without `on_error`, Role-Aware Dashboard Toolkit emits a `RuntimeWarning`

Runtime error records contain:

- `stage`
- `source`
- `exception_type`
- `error_type`
- `message`

UI fallbacks add a `fallback` field. Paths in diagnostic text are redacted.

## Cleanup

`cleanup_runtime()` can stop an audit writer, clear selected object references,
run garbage collection, and optionally ask an installed Torch runtime to clear
its CUDA cache. Role-Aware Dashboard Toolkit does not install Torch. Missing optional runtimes are
no-ops; broken imports and cleanup failures are returned in `error_records`.

Cleanup is best effort. Callers must inspect the returned report rather than
assuming every stage succeeded.

## Audit writer diagnostics

Audit persistence keeps memory and disk outcomes separate. A disk startup,
append, or bounded-shutdown failure remains visible through writer status and
runtime diagnostics while in-memory events remain readable. Callers should
surface the error and avoid starting an overlapping writer when ownership is
uncertain.

## Data rules

- metric values should be finite numbers
- labels and health fields should be small descriptive values
- timestamps should be UTC ISO 8601 when supplied
- telemetry must not contain credentials
- health summaries must not be treated as authorization decisions
