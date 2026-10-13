# Show measurements and capture their evidence

A telemetry hook returns numeric measurements with optional timestamp, labels
and health context:

```python
observability = radt.ObservabilityConfig(
    enabled=True,
    telemetry_hook=lambda: {
        "metrics": {"queue_depth": 12, "latency_ms": 18.4},
        "source": "local-example", "health": {"status": "ok"},
    },
    history_limit=30,
)
config = radt.DashboardConfig(auth_mode="demo", registry=registry, observability=observability)
```

Replace the example numbers with an authorized data source. Sampling occurs on
eligible renders; this is not a background monitoring loop. No sampling occurs
when observability is hidden or the role lacks `can_view_metrics`.

Samples are normalized to schema version, `ts`, numeric `metrics`, `labels`,
`source`, `service` and `health`. Nested metrics use dotted paths; non-finite
numbers are excluded/sanitized. Supply UTC ISO-8601 timestamps when available.

Checkpoints capture the last successfully displayed normalized sample, including
its original timestamp. They do not make another hook call at capture.
Sampling failures remain visible and retain the last successful sample; a
retained sample must not be described as fresh. Samples copied into checkpoints
are detached from later mutations.

Keep credentials and unnecessary personal data out of telemetry. Health labels
are descriptive and never authorize an action.

Verify a changed measurement appears, capture a checkpoint, and compare its
sample timestamp and metrics with the displayed sample. Make the source fail
and confirm the warning and unchanged timestamp. Check that a role lacking
metrics permission neither samples nor captures prior visible telemetry.
