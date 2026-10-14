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
- optional `units`: a mapping from metric names to host-supplied unit strings

A telemetry hook may return that full shape or any nested numeric payload.
Nested metric names are retained with dotted paths, repeated keys keep the
maximum observed value, and booleans are ignored.

```python
import role_aware_dashboard_toolkit as radt

config = radt.ObservabilityConfig(
    enabled=True,
    telemetry_hook=lambda: {
        "metrics": {"latency_ms": 18.4, "queue": {"depth": 2}},
        "units": {"latency_ms": "ms", "queue.depth": "requests", "depth": "requests"},
        "labels": {"region": "east"},
        "health": {"status": "ok"},
        "source": "service",
    },
    history_limit=30,
)
```

The core summary remains dictionary-based. Install `role-aware-dashboard-toolkit[pandas]` only for
dataframe-backed history views.

Units are optional and descriptive. Supply them by the normalized metric name,
including a dotted path or retained leaf alias when needed. Normalized samples
retain non-empty unit strings only for retained metrics. The toolkit does not
infer units from names or convert between units.

## Checkpoint capture

The dashboard stores a detached copy of the last successfully displayed,
normalized sample. A native checkpoint copies that sample, including its original
`ts`, rather than calling the telemetry hook again. The sample timestamp may
precede the checkpoint timestamp and should be used to judge freshness.

A sampling failure shows a warning and retains the last successful sample.
It does not manufacture a fresh timestamp. A role without `can_view_metrics`
does not sample telemetry or copy a prior role's sample into a checkpoint.

## Compare recorded outcomes

```python
comparison = radt.compare_checkpoints(left, right, include_telemetry=True)
outcomes = comparison["telemetry_comparison"]
print(outcomes["left_sample_ts"], outcomes["right_sample_ts"])
print(outcomes["metrics"])
```

Existing calls keep their original result shape. With `include_telemetry=True`,
each recorded metric appears under `telemetry_comparison.metrics`, including
unchanged measurements. Each row contains `from`, `to`, `from_unit`, `to_unit`,
`delta` and `status`. The delta is right minus left. It is calculated only for
finite numeric values with equal unit strings. The delta is the exact difference
of the endpoints' shortest decimal forms, rounded once to a float (0.35 minus
0.1 is 0.25, not 0.24999999999999997); `summarize_observability` drift deltas
use the same rule. Two absent units mean unspecified
units; one absent unit and one stated unit are a mismatch. Unit strings are
trimmed and compared exactly, without case folding or conversion.

Missing values produce `missing_left` or `missing_right`; invalid values,
including booleans and numeric strings, produce `invalid_value`. These rows
retain the available finite endpoint but have `delta=None`. A `unit_mismatch`
also has no delta. Finite endpoints whose subtraction overflows produce
`non_finite_delta`. Otherwise the status is `comparable`. Invalid values removed
during earlier sample normalization appear as missing when compared later.

Legacy flat telemetry maps are also accepted. Nested maps use dotted paths and
repeated list values retain their finite maximum. Already normalized metric names
remain distinct. Metadata such as health and labels is not compared as metrics.
Original sample timestamps appear as `left_sample_ts` and `right_sample_ts`;
missing timestamps remain empty instead of substituting the checkpoint time.

`compare_runs(left, right, include_telemetry=True)` compares the final checkpoint
in each run's stored order and includes its `left_checkpoint_id` and
`right_checkpoint_id`. If that checkpoint has no telemetry, an older checkpoint
is not substituted. This comparison does not aggregate all samples in a run.

Native runbook comparisons show the observations beside control changes, subject
to `can_view_metrics`, which also governs checkpoint telemetry. Direct Python
callers own authorization to view their supplied records. These observations do
not establish causality, statistical significance, or whether a larger value is
better. The host application remains responsible for consistent measurement
definitions, sampling windows and units.

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
